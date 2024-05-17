#!/usr/bin/env python3

import hashlib
import os
import subprocess
import sys 

import pandas as pd
pd.set_option('display.max_rows', None)

from loguru import logger

import pyshark
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import binascii

import json
import yaml

def get_cert_cn(cert_hex_colon):
    cert_hex = cert_hex_colon.replace(':', '')
    cert_bytes = binascii.unhexlify(cert_hex)
    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    subject = cert.subject
    cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return cn

# tcp and udp streams dictionaries, keyed by stream number
tcp_streams = {}
udp_streams = {}

# dns streams, keyed by by src_ip/dst_ip/dst_port
dns_streams = {}

def get_packet_direction(stream, src_ip, src_port, dst_ip, dst_port):
    if stream['src'] == src_ip and stream['srcport'] == src_port and \
        stream['dst'] == dst_ip and stream['dstport'] == dst_port:
        return 1 # client to server
    if stream['src'] == dst_ip and stream['srcport'] == dst_port and \
        stream['dst'] == src_ip and stream['dstport'] == src_port:
        return 2 # server to client
    else:
        raise RuntimeError("unclear direction")
    
def handle_packet(packet, stats):
    if 'ip' in packet:
        stats['ip'] += 1
        #ip_version = 4
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
    elif 'ipv6' in packet:
        stats['ipv6'] += 1
        #ip_version = 6
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
    else:
        stats['non-ip'] += 1
        return

    if 'tcp' in packet:
        stats['tcp'] += 1
        handle_tcp_packet(packet, src_ip, dst_ip, stats)
    elif 'udp' in packet:
        stats['udp'] += 1
        handle_udp_packet(packet, src_ip, dst_ip, stats)
    else:
        stats['non-tcp-udp'] += 1

def handle_udp_packet(packet, src_ip, dst_ip, stats):
    if 'DNS' in packet:
        handle_dns_packet(packet, src_ip, dst_ip, stats)
        stats['dns'] += 1
    else:
        _udp_stream, _direction = get_udp_stream(packet, src_ip, dst_ip)

def get_dns_stream(packet, src_ip, dst_ip, query):
    dns_stream_key1 = f"{src_ip}/{dst_ip}/{packet.udp.dstport}/{query}"
    if dns_stream_key1 in dns_streams:
        stream = dns_streams[dns_stream_key1]
    else:
        dns_stream_key2 = f"{dst_ip}/{src_ip}/{packet.udp.srcport}/{query}"
        if dns_stream_key2 in dns_streams:
            stream = dns_streams[dns_stream_key2]
        else:
            stream = {
                'stream': int(packet.udp.stream),
                'frame_number': int(packet.frame_info.number),
                'src': src_ip,
                'dst': dst_ip,
                'dstport': packet.udp.dstport,
                'query': query,
                'q_count': 1,
                'responses': {}
            }
            dns_streams[dns_stream_key1] = stream

    stream['q_count'] += 1

    return stream

def get_udp_stream(packet, src_ip, dst_ip):
    stream_id = int(packet.udp.stream)
    if stream_id in udp_streams:
        stream = udp_streams[stream_id]
        direction = get_packet_direction(stream, src_ip, packet.udp.srcport, dst_ip, packet.udp.dstport)
    else:
        stream = {
            'stream': int(packet.udp.stream),
            'stream': stream_id,
            'src': src_ip,
            'srcport': packet.udp.srcport,
            'dst': dst_ip,
            'dstport': packet.udp.dstport
        }

        udp_streams[stream_id] = stream
        direction = 1 # from client to server

    return stream, direction

def get_dns_answer_repr(packet):
    """
        This function returns a string representation of the DNS packet, both query and answer.
    """
    lines = ""
    do_collect = False

    for line in packet.dns._get_all_field_lines():
        # holymoly, this is a mess ... FIXME
        if line.startswith('\tTime:') or line.startswith('\tRequest In:'):
            continue

        if line == '\tQueries\n':
            do_collect = True
        if do_collect:
            lines += line
    
    return lines


def __get_dns_answer(packet):
    """
        Returns a string representation of the DNS response.
        Except this approach oes not really work, because pyshark is nuts.
    """
    resp_fields = {k: packet.dns.get(k) for k in packet.dns.field_names if k.startswith('resp_')}

    count_answers = int(str(packet.dns.count_answers))
    if int(packet.dns.flags_rcode) == 0 and count_answers > 0:
        assert count_answers <= 1 # FIXME - handle multiple answers

        resp_type = getattr(packet.dns, 'resp_type')
        import pdb; pdb.set_trace()

        # join all answer records
        answers = []
        for _ in range(count_answers):
            # select all fields where name starts with 'resp_'
            resp_fields = {k: packet.dns.get(k) for k in packet.dns.field_names if k.startswith('resp_')}
            # merge their values into a single string
            dns_response_record = '/'.join([f"{k}={v}" for k,v in resp_fields.items()])
            answers.append(dns_response_record)
        answer = ', '.join(answers) # maybe sort answers before joining? wipe TTLs?
    else:
        answer = f"rcode={packet.dns.flags_rcode}/ancount={packet.dns.count_answers}"

    return answer

def handle_dns_packet(packet, src_ip, dst_ip, stats):
    assert int(str(packet.dns.count_queries)) == 1 # FIXME - handle multiple queries
    query_type = packet.dns.qry_type
    query_name = packet.dns.qry_name
    query = f"{query_type}/{query_name}"

    dns_stream = get_dns_stream(packet, src_ip, dst_ip, query)

    # https://stackoverflow.com/questions/715417/converting-from-a-string-to-boolean-in-python
    def str2bool(v):
        if v == "True":
            return True
        elif v == "False":
            return False
        else:
            raise ValueError(f"invalid boolean value {v}")
    has_response = str2bool(packet.dns.flags_response)
    # WTF? int(packet.dns.flags_response) == 0

    if has_response:
        #if query not in dns_stream['queries']:
        #    # this query was not seen before - should not happen
        #    raise RuntimeError(f"response without a query: {packet.frame_info.number}")
        #else:
        #    # this query was seen before, increment the response count
        responses = dns_stream['responses']

        answer = get_dns_answer_repr(packet)
            
        if answer not in responses:
            responses[answer] = {
                'frame_number': int(packet.frame_info.number),
                'count': 1
            }
        else:
            responses[answer]['count'] += 1

def get_tcp_stream(packet, src_ip, dst_ip):
    src_port = int(packet.tcp.srcport)
    dst_port = int(packet.tcp.dstport)

    stream_id = int(packet.tcp.stream)
    if stream_id in tcp_streams:
        stream = tcp_streams[stream_id]
        direction = get_packet_direction(stream, src_ip, src_port, dst_ip, dst_port)
    else:
        stream = {
            'frame_number': int(packet.frame_info.number),
            'stream': stream_id,
            'syn': packet.tcp.flags.int_value == 2, # SYN
            'src': src_ip,
            'srcport': src_port,
            'dst': dst_ip,
            'dstport': dst_port
        }

        tcp_streams[stream_id] = stream
        direction = 1 # from client to server
    
    return stream, direction

def handle_tcp_packet(packet, src_ip, dst_ip, stats):
    stream, direction = get_tcp_stream(packet, src_ip, dst_ip)

    tls_field = 'tls' if 'tls' in packet else 'ssl' if 'ssl' in packet else None
    if tls_field is not None:
        handle_tls_packet(packet, stream, direction, tls_field)
        stats['tls'] += 1


def safeset(dict, key, value):
    if key in dict:
        if dict[key] != value:
            raise RuntimeException(f"caught overwrite of key '{key}' old value '{dict['key']} by value '{value}'")
    else:
        dict[key] = value

def handle_tls_packet(packet, stream, direction, tls_field):
    if 'handshake_extensions_server_name' in packet[tls_field].field_names \
        and packet[tls_field].handshake_extensions_server_name != '':
        sni = packet[tls_field].handshake_extensions_server_name.lower()
        safeset(stream, 'sni', sni)

    if 'handshake_ja3' in packet[tls_field].field_names:
        ja3 = packet[tls_field].handshake_ja3
        safeset(stream, 'ja3', ja3)

    if 'handshake_ja3s' in packet[tls_field].field_names:
        ja3s = packet[tls_field].handshake_ja3s
        safeset(stream, 'ja3s', ja3s)

    if 'handshake_certificates' in packet[tls_field].field_names:
        cert = packet[tls_field].handshake_certificate
        cn = get_cert_cn(cert)

        if direction == 1: # client
            field_name = f"client_cn"
        elif direction == 2: # server
            field_name = f"server_cn"

        safeset(stream, field_name, cn)

def load_pcap_file_timestamps(pcap_files):
    """
        Reads the timestamp of the first packet in each pcap file.
        Returns a dictionary with timestamps as keys and file names as values.
    """
    timestamps = {}

    for i, file in enumerate(pcap_files):
        # do not allow duplicates in the list of pcap files
        if file in pcap_files[:i]:
            raise RuntimeError(f"duplicate pcap file {file}")

        # get the timestamp of the first packet in the file
        cap = pyshark.FileCapture(file)
        for packet in cap:
            break
        timestamp = float(packet.frame_info.time_epoch)
        cap.close()
        logger.info(f"pcap file {file} timestamp {timestamp}")

        # save the timestamp
        timestamps[timestamp] = file

    return timestamps

def open_merged_pcap_file(timestamp_ordered_pcap_files):
    # generate a merged file if it does not exist yet
    pcap_files_hash = hashlib.md5(''.join(timestamp_ordered_pcap_files).encode()).hexdigest()
    merged_file = f"{pcap_files_hash}.pcapng"
    if os.path.exists(merged_file):
        logger.info(f"file {merged_file} already exists, skipping mergecap")
    else:
        cmd = ['mergecap', '-w', merged_file] + timestamp_ordered_pcap_files
        logger.debug(f"running mergecap: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        logger.info(f"mergecap done")

    # open the merged file and return it
    cap = pyshark.FileCapture(merged_file)
    return cap

def read_packets(pcap_files):
    """
        Reads the packets from the given pcap files.
        Returns packets in chronological order, along with the name of pcap file it belongs to.
    """
    # order the pcap files by timestamp
    pcap_file_timestamps = load_pcap_file_timestamps(pcap_files)
    ordered_pcap_timestamps = sorted(pcap_file_timestamps.keys())
    timestamp_ordered_pcap_files = [pcap_file_timestamps[timestamp] for timestamp in ordered_pcap_timestamps]
    assert pcap_files == timestamp_ordered_pcap_files # just for troubleshooting for now, to be removed
    logger.debug(f"ordered pcap files: {timestamp_ordered_pcap_files}")

    cap = open_merged_pcap_file(timestamp_ordered_pcap_files)

    current_pcap_file_i = 0
    current_pcap_file = None
    next_pcap_file_timestamp = None

    def roll():
        nonlocal current_pcap_file_i
        nonlocal current_pcap_file
        nonlocal next_pcap_file_timestamp

        logger.debug(f"roll  in: current_pcap_file_i {current_pcap_file_i} current_pcap_file {current_pcap_file} next_pcap_file_timestamp {next_pcap_file_timestamp}")

        current_pcap_file = timestamp_ordered_pcap_files[current_pcap_file_i]

        if len(timestamp_ordered_pcap_files) > current_pcap_file_i + 1:
            next_pcap_file_timestamp = ordered_pcap_timestamps[current_pcap_file_i + 1]
        else:
            next_pcap_file_timestamp = None

        logger.debug(f"roll out: current_pcap_file {current_pcap_file}, next_pcap_file_timestamp {next_pcap_file_timestamp}")

    roll()

    for packet in cap:  
        if next_pcap_file_timestamp is not None and float(packet.frame_info.time_epoch) >= next_pcap_file_timestamp:
            current_pcap_file_i += 1
            roll()

        yield packet, current_pcap_file

def handle_pcap_file_roll(current_pcap_file, new_pcap_file, stats):
    """
        This function is called when the pcap file rolls.
    """
    logger.info(f"pcap_file_roll: current_pcap_file={current_pcap_file}")

    print(f"\n## {current_pcap_file}\n")

    stats['#tcp_streams'] = len(tcp_streams)
    stats['#udp_streams'] = len(udp_streams)
    stats['#dns_streams'] = len(dns_streams)
    logger.info(f"{stats}")

    dump_tcp_streams()
    dump_udp_streams()
    dump_dns_streams()

    print("\n"); sys.stdout.flush() # flush stdout, otherwise it gets out of sync with stderr

    logger.info(f"pcap_file_roll: new_pcap_file={new_pcap_file}")

def aggregate(df, irrelevant_columns):
    relevant_columns = [col for col in df.columns if col not in irrelevant_columns]

    df = df.fillna('N/A')
    df = df.groupby(by=relevant_columns).size().reset_index(name='<count>')
    df = df.sort_values(by=relevant_columns)

    return df

def dump_tcp_streams(dump_all=False, dump_aggregated=False):
    # load all tcp streams into a dataframe, make sure all columns are present
    for tcp_stream in tcp_streams:
        for key in ['sni', 'ja3', 'ja3s', 'client_cn', 'server_cn']:
            if key not in tcp_streams[tcp_stream]:
                tcp_streams[tcp_stream][key] = None

    stream_list = sorted(list(tcp_streams.values()), key=lambda x: x['stream'])
    df = pd.DataFrame(stream_list)

    # -- all streams --
    if dump_all:
        print("\nALL TCP STREAMS:\n")     
        print(df.to_markdown())

    # -- aggregated streams --
    aggregated_df = aggregate(df, ["frame_number", "stream", "srcport"])
    if dump_aggregated:
        print("\nAGGREGATED TCP STREAMS:\n")     
        print(aggregated_df.to_markdown())

    # -- new streams --
    if True:
        print("\nNEW TCP STREAMS:\n")     
        new_df = get_new_streams('tcp', aggregated_df)
        print(new_df.to_markdown())

# this dictionary is used to tell if the flow is new or known
known_streams = {}

def get_new_streams(proto, df):
    # create a new dataframe with the same columns as the original one
    new_df = pd.DataFrame(columns=df.columns)

    # iterate over all rows, for each row construct a key value, hash of all values except the count
    # if the key is not in known dict, add it to the known dict and to display_df
    for _, row in df.iterrows():
        key = tuple([proto] + list(row.values[:-1])) # here we exclude the last column, which is <count>
        if key not in known_streams:
            known_streams[key] = 1
            new_df.loc[len(new_df)] = row
        else:
            known_streams[key] += 1

    return new_df

def dump_udp_streams(dump_all=False, dump_aggregated=False):
    # load all udp streams into a dataframe
    stream_list = sorted(list(udp_streams.values()), key=lambda x: x['stream'])
    df = pd.DataFrame(stream_list)

    # -- all streams --
    if dump_all:
        print("\nALL UDP STREAMS:\n")     
        print(df.to_markdown())

    # -- aggregated streams --
    aggregated_df = aggregate(df, ["frame_number", "stream", "srcport"])
    if dump_aggregated:
        print("\nAGGREGATED UDP STREAMS:\n")     
        print(aggregated_df.to_markdown())

    # -- new streams --
    if True:
        print("\nNEW UDP STREAMS:\n")     
        new_df = get_new_streams('udp', aggregated_df)
        print(new_df.to_markdown())

def pretty_format_queries(all_df):
    # reformat dns queries to make it more compact and readable
    def format_queries(queries):
        queries = json.loads(json.dumps(queries, indent=4)) # convert to JSON and back to get rid of garbage
        return yaml.dump(queries)
    
    pretty_all_df = all_df.copy(deep=True)
    pretty_all_df['responses'] = pretty_all_df['responses'].apply(lambda x: format_queries(x))

    return pretty_all_df

def dump_dns_streams(dump_all=False):
    # load all dns streams into a dataframe
    stream_list = sorted(list(dns_streams.values()), key=lambda x: x['stream'])

    all_df = pd.DataFrame(stream_list)

    # -- all streams --
    if dump_all:        
        print("\nALL DNS STREAMS:\n")     
        print(pretty_format_queries(all_df).to_markdown())

    # -- new streams --
    if True:
        clean_df = all_df.copy(deep=True)
        # drop q_count column
        if 'q_count' in clean_df.columns:
            clean_df = clean_df.drop(columns=['q_count'])
        # drop q_count from the responses
        def cleanup_responses(responses):
            return {k: v for k, v in responses.items() if k != 'q_count'}
        clean_df['responses'] = clean_df['responses'].apply(lambda x: cleanup_responses(x))
        new_df = get_new_streams('dns', clean_df)

        print("\nNEW DNS STREAMS:\n")
        print(pretty_format_queries(new_df).to_markdown())

def main():
    pcap_files = sys.argv[1:]
    current_pcap_file = None
    stats = {counter: 0 for counter in ['non-ip', 'ip', 'ipv6', 'tcp', 'udp', 'non-tcp-udp', 'tls', 'dns']}

    for packet, pcap_file in read_packets(pcap_files):

        if current_pcap_file is None:
            current_pcap_file = pcap_file
        elif current_pcap_file is not None and current_pcap_file != pcap_file:
            handle_pcap_file_roll(current_pcap_file, pcap_file, stats)
            current_pcap_file = pcap_file

        try:
            handle_packet(packet, stats)
        except Exception as e:
            logger.error(f"error in packet {packet} in file {pcap_file}: {e}")

            import pdb; pdb.set_trace()
            raise

    handle_pcap_file_roll(current_pcap_file, None, stats)
    
if __name__ == '__main__':
    main()
