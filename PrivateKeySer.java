package ransomware;

import java.io.Serializable;
import java.security.PrivateKey;

public class PrivateKeySer implements Serializable{
	
	private static final long serialVersionUID = -283456957127407086L;
	private PrivateKey publicKey;
    
    public PrivateKeySer(PrivateKey key) {
    	publicKey = key;
    }
    
    public PrivateKey getPrivateKey() {
    	return publicKey;
    }
}
