package co.poynt.samples;

public class Main {

	public static void main(String [] args) throws Exception {
		String accessToken = Poynt.getAccessToken();
		System.out.println("access token: " + accessToken);
	}

}
