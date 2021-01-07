package ransomware;

import java.io.Serializable;
import java.security.PublicKey;

public class PublicKeySer implements Serializable{

	private static final long serialVersionUID = -6132864229578478926L;
    private PublicKey publicKey;
    
    public PublicKeySer(PublicKey key) {
    	publicKey = key;
    }
    
    public PublicKey getPublicKey() {
    	return publicKey;
    }
}
