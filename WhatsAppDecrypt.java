import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import jeb.api.IScript;
import jeb.api.JebInstance;
import jeb.api.dex.Dex;
import jeb.api.dex.DexCodeItem;
import jeb.api.dex.DexDalvikInstruction;
import jeb.api.ui.JavaView;
import jeb.api.ui.View;

public class WhatsAppPlugin implements IScript {
	
	char[] keys={0x53,0x26,0x55,0x3A,0x8}; // Change keys here

	public String decode_string(String input)
	{
		char [] temp=input.toCharArray();
		for (int i=0;i<input.length();i++)
		{
			temp[i]=(char)(temp[i]^keys[i%5]);
		}
		String output=new String(temp).intern();
		return output;
	}
	
	public void run(JebInstance jeb)
	{
		Dex dex=jeb.getDex();
		JavaView view=(JavaView)jeb.getUI().getView(View.Type.JAVA);
		String methodname=view.getCodePosition().getSignature();
		jeb.print(methodname);
		DexCodeItem code=dex.getMethodData(methodname).getCodeItem();
		if (code==null) return;
		List<DexDalvikInstruction> list=code.getInstructions();
		HashMap<Integer, String> staticstrings = new HashMap<Integer, String>();
		
		for (DexDalvikInstruction insn: list)
		{
			String mnemonic=insn.getMnemonic();
			if (!mnemonic.contains("const-string")) continue;
			long stringindex=insn.getParameters()[1].getValue();
			String cryptstring=dex.getString((int)stringindex);
			if (staticstrings.containsKey(stringindex)==false)
			{
				staticstrings.put((int)stringindex,cryptstring);
			}
		}
		for(int key : staticstrings.keySet())
		{
			String value=decode_string(staticstrings.get(key));
			String str=String.valueOf(key)+": "+value;
			dex.setString(key, value);
			jeb.print(str);
		}
	}
}
