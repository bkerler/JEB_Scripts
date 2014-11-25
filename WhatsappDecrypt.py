import sys
import os
import time
import binascii
from jeb.api import IScript
from jeb.api import EngineOption
from jeb.api.ui import View
from jeb.api.dex import Dex
from jeb.api.ast import Class, Field, Method, Call, Constant, StaticField, NewArray

class WhatsappDecrypt(IScript):
  
  def decode_string(self,encoded_str, key):
   decoded_str = ''
   for i in range(len(encoded_str)):
    decoded_str += chr(ord(encoded_str[i]) ^ key[i % 5])
   return decoded_str

  def run(self, jeb):
    self.keys = [0x29,0x49,0x70,0x1C,0x71] #Change keys here (see switch statements)
    self.jeb = jeb
    self.dex = self.jeb.getDex()
    if not self.dex:
      print 'Error! Please provide an input file.'
      sef.jeb.exit()

    v = self.jeb.getUI().getView(View.Type.JAVA)
    if not v:
      print 'Switch to the Java view, position the caret somewhere inside the method to be decompiled'
      return
    self.msig=v.getCodePosition().getSignature()
    print(self.msig)
	
    md = self.dex.getMethodData(self.msig)
    if not md:
     print ("Failed get Method Data")
     return
    
    code = md.getCodeItem()
    if not code:
     return
    
    stringlist = {}
    for insn in code.getInstructions():
     if not insn.getMnemonic() in ('const-string', 'const-string/jumbo'):
      continue
     stringindex = insn.getParameters()[1].getValue()
     s = self.dex.getString(stringindex)
     s2 = self.decode_string(s,self.keys)
     if (stringindex not in stringlist):
      stringlist[stringindex]=s2
    for m in stringlist:
     print (hex(m)+": "+stringlist[m])
     self.dex.setString(m,stringlist[m])
    print("Done")
    return