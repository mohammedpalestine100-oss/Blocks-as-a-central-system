package com.creata.poa.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class CentralAuthority {
  private final String name;      // "creata"
  private byte[] secretKey;       // HMAC key (قابل للتغيير عبر import)

  public CentralAuthority(String name, byte[] secretKey) {
    this.name = name; this.secretKey = secretKey.clone();
  }
  public String name(){ return name; }
  public byte[] key(){ return secretKey; }
  public void importKey(byte[] k){ this.secretKey = k.clone(); }

  public String sign(String headerWithoutSig) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
      return CryptoUtils.bytesToHex(mac.doFinal(headerWithoutSig.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e){ throw new RuntimeException("HMAC failure", e); }
  }
  public boolean verify(Block b) {
    String sig = sign(b.headerWithoutSignature());
    if (!Objects.equals(sig, b.getAuthoritySignature())) return false;
    String recomputedHash = CryptoUtils.sha256(b.headerWithSignature().getBytes(StandardCharsets.UTF_8));
    return Objects.equals(recomputedHash, b.getHash());
  }
}
