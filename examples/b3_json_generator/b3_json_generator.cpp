#include <iostream>
#include <string>
#include <fstream>
#include <endian.h>
#include <assert.h>

#include <mfast.h>
#include <mfast/coder/fast_decoder.h>
#include <mfast/json/json.h>
#include <mfast/xml_parser/dynamic_templates_description.h>

//#include "templates_PUMA.h"
#include "b3_template.h"

using std::string;
using std::ostringstream;
using std::cout;
using std::endl;

using mfast::templates_description;
using mfast::dynamic_templates_description;
using mfast::fast_decoder;
using mfast::message_cref;
using mfast::ascii_string_cref;
using mfast::json::encode;

int parse_one_packet(const char* fast_message, int msg_len, std::ofstream &out_file, int last_msg_seq) {
  //const templates_description* descriptions[] = {templates_PUMA::templates_description::instance()};
  const templates_description* descriptions[] = {b3_template::templates_description::instance()};

  fast_decoder decoder;
  decoder.include(descriptions);

  const char* start = fast_message; // .c_str();
  const char* end = start + msg_len; //fast_message.length();

  try {
    int loop_count = 0;
    while (start < end) 
    {
      loop_count += 1;
      //cout << "Loop Index: " << loop_count << endl;
      //cout << "Start: " << int64_t(start-fast_message) << " End:" << int64_t(end-fast_message) << endl;
      auto msg = decoder.decode(start, end);
      //cout << "Start: " << int64_t(start-fast_message) << " End:" << int64_t(end-fast_message) << endl;
      //cout << "Template id: " << msg.id() << " Size: " << msg_len << endl;
      int msg_seq_num = last_msg_seq;
      switch (msg.id()) {
        case 141: {
          auto cref = static_cast<b3_template::MDSecurityList_141_cref>(msg);
          msg_seq_num = cref.get_MsgSeqNum().value();
          break;
        } 
        case 153: {
          auto cref = static_cast<b3_template::MDSnapshotFullRefresh_153_cref>(msg);
          msg_seq_num = cref.get_MsgSeqNum().value();
          break;
        }
        case 122: {
          auto cref = static_cast<b3_template::MDSequenceReset_cref>(msg);
          msg_seq_num = cref.get_MsgSeqNum().value();
          break;
        }
        default: {
          cout << "msg_id: " << msg.id() << endl;
          assert(false);
          break;
        }
      }
      //cout << "MsgSeqNum: " << msg_seq_num << endl;

      last_msg_seq = msg_seq_num;

      ostringstream json_message;
      bool result = encode(json_message, msg, 0);
      if (result) {
        out_file << json_message.str() << endl;
      }
    }
    //cout << "Loop count: " << loop_count << endl;

    return last_msg_seq;
  }
  catch (...) {
    cout << "Error decoding" << endl;
    return last_msg_seq;
  }
}

#pragma pack(1)
struct TechnicalMessageHeader {
  uint32_t msg_seq_num;
  uint16_t no_chunks;
  uint16_t current_chunk;
  uint16_t msg_length;

  void reverseEndianness() {
    msg_seq_num = __builtin_bswap32(msg_seq_num);
    no_chunks = __builtin_bswap16(no_chunks);
    current_chunk = __builtin_bswap16(current_chunk);
    msg_length = __builtin_bswap16(msg_length);
  }
};
#pragma pack()

int main(int, char* argv[]) {
  std::ifstream inp_file;
  std::ofstream out_file;
  char buffer[1000000];
  uint32_t pkt_size;
  //uint16_t chunk_idx, num_chunks;
  uint32_t data_size = 0;
  int ts_count;
  uint64_t ts;
  //char tech_header[10];
  uint16_t last_chunk = 0;

  inp_file.open(argv[1], std::ios::in|std::ios::binary);
  out_file.open(argv[2], std::ios::out);
  int last_msg_seq_num = 0;
  bool drop_occurred = true;
  int cycle_count = 0;
  while (true) {
    inp_file.read(reinterpret_cast<char *>(&ts_count), 1);
    //cout << ts_count << endl;
    for(int i = 0; i < ts_count; ++i) {
      inp_file.read(reinterpret_cast<char *>(&ts), 8);
      //cout << ts << endl;
    }

    inp_file.read(reinterpret_cast<char *>(&pkt_size), 4);
    //cout << pkt_size << endl;
    if (pkt_size == 1) {
      inp_file.read(reinterpret_cast<char *>(&pkt_size), 1);
      continue;
    }

    uint16_t cur_packet_parsed = 0;
    while ((cur_packet_parsed < pkt_size) && (inp_file.tellg() >= 0)){
      TechnicalMessageHeader tech_header;
      inp_file.read(reinterpret_cast<char *>(&tech_header), 10);
      tech_header.reverseEndianness();

      inp_file.read(&buffer[data_size], tech_header.msg_length);
      data_size += tech_header.msg_length;
      cur_packet_parsed += 10 + tech_header.msg_length;
      //cout << "Packet size: " << pkt_size << " at file pos: " << inp_file.tellg() << endl;
      //cout << "Message length: " << tech_header.msg_length << endl;

      //cout << "Copied chunk_idx: " << tech_header.current_chunk << " from num_chunks: " << tech_header.no_chunks << endl;
      //cout << "Chunk size: " << pkt_size - 10 << " out of total size: " << tech_header.msg_length << endl;
      if (tech_header.current_chunk != tech_header.no_chunks) {
        last_chunk = tech_header.current_chunk;
        continue;
      }
      if (tech_header.current_chunk > 1) {
        if (last_chunk + 1 != tech_header.current_chunk) {
          cout << "Dropping unexpected chunk at " << static_cast<uint32_t>(inp_file.tellg()) - data_size << endl;
          data_size = 0;
          continue;
        }
      }

      if (last_msg_seq_num == 0) {
        //cout << "Starting cycle: " << cycle_count << endl;
        drop_occurred = false;
      }
      int cur_msg_seq_num = parse_one_packet(buffer, data_size, out_file, last_msg_seq_num);
      //cout << "Captured msg_seq_num: " << cur_msg_seq_num << endl;
      if (cur_msg_seq_num != last_msg_seq_num + 1) {
        if (cur_msg_seq_num > 1) {
          cout << "Drop detected: " << cur_msg_seq_num << " instead of " << last_msg_seq_num + 1 << " in cycle: " << cycle_count << endl;
          drop_occurred = true;
        }
      }
      if (cur_msg_seq_num == 1 && last_msg_seq_num >= 1) {
        //cout << "Cycle: " << cycle_count << " complete. Drop occured: " << drop_occurred << endl;
        cycle_count += 1;
        drop_occurred = false;
        if (cur_packet_parsed < pkt_size) {
          //cout << "Starting cycle: " << cycle_count << endl;
        }
      }

      last_msg_seq_num = cur_msg_seq_num;

      data_size = 0;
      last_chunk = 0;
      //cout << "File pos: " << inp_file.tellg() << endl;
      if (inp_file.tellg() < 0) break;
    }
    if (inp_file.tellg() < 0) break;
    if (!drop_occurred && (cycle_count > 10)) break;
  }

  out_file.close();
  inp_file.close();
}
