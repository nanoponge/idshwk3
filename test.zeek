global agentTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) 
{
  if(name=="USER-AGENT")
  {
    local sourceIp: addr = c$id$orig_h;
    if (sourceIp in agentTable) {
          add (agentTable[sourceIp])[to_lower(value)];
        } else {
          agentTable[sourceIp] = set(to_lower(value));
        }
  }
}

event zeek_done() 
{
    for (sourceIP in agentTable) {
        if (|agentTable[sourceIP]| >= 3) {
            print(addr_to_uri(sourceIP) + " is a proxy");
        }
    }
}
