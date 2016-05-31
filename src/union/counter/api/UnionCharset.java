package union.counter.api;

public class UnionCharset {
	private static String charSetName = "GBK";

	public static String getCharSetName() {
		return charSetName;
	}

	public static void setCharSetName(String charSetName) {
		UnionCharset.charSetName = charSetName;
	}
	
}
