package re.bytecode.obfuscat.gwt.client;

import com.google.gwt.core.client.EntryPoint;

import re.bytecode.obfuscat.Obfuscat;


public class ObfuscatGWT implements EntryPoint {

	
	native void consoleLog(String message) /*-{
    	console.log( "msg:" + message );
	}-*/;
	


	private native void setUpAPI()/*-{
		$wnd.generate = $entry(@re.bytecode.obfuscat.gwt.client.JSAPI::generate(ILre/bytecode/obfuscat/cfg/Function;));
	    $wnd.buildKeyBuilder = $entry(@re.bytecode.obfuscat.gwt.client.JSAPI::buildKeyBuilder(ILjava/lang/String;));
	    $wnd.buildVerifyBuilder = $entry(@re.bytecode.obfuscat.gwt.client.JSAPI::buildVerifyBuilder(ILjava/lang/String;));
	    $wnd.buildSample = $entry(@re.bytecode.obfuscat.gwt.client.JSAPI::buildSample(Ljava/lang/String;Ljava/lang/String;Z));
	    $wnd.obfuscate = $entry(@re.bytecode.obfuscat.gwt.client.JSAPI::obfuscate(ILjava/lang/String;Lre/bytecode/obfuscat/cfg/Function;));
	}-*/;
	
	public void onModuleLoad() {
		Obfuscat.setReadFileFunction(JSAPI.readFile);
		setUpAPI();
	}
}
