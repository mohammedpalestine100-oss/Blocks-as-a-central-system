package com.creata.poa.core;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class CryptoUtils {
  public static String sha256(byte[] data) {
    try {
      MessageDigest d = MessageDigest.getInstance("SHA-256");
      return bytesToHex(d.digest(data));
    } catch (Exception e) { throw new RuntimeException(e); }
  }
  public static String bytesToHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString();
  }
  private static byte[] hexToBytes(String hex) {
    int n = hex.length(); byte[] out = new byte[n/2];
    for (int i=0;i<n;i+=2) out[i/2]=(byte)Integer.parseInt(hex.substring(i,i+2),16);
    return out;
  }
  public static String merkleRoot(List<String> leavesHex) {
    if (leavesHex == null || leavesHex.isEmpty()) return sha256(new byte[0]);
    List<byte[]> layer = new ArrayList<>();
    for (String h : leavesHex) layer.add(hexToBytes(h));
    while (layer.size() > 1) {
      List<byte[]> next = new ArrayList<>();
      for (int i=0;i<layer.size();i+=2) {
        byte[] L = layer.get(i);
        byte[] R = (i+1<layer.size()) ? layer.get(i+1) : L;
        byte[] both = new byte[L.length+R.length];
        System.arraycopy(L,0,both,0,L.length);
        System.arraycopy(R,0,both,L.length,R.length);
        next.add(hexToBytes(sha256(both)));
      }
      layer = next;
    }
    return bytesToHex(layer.get(0));
  }
}


package com.creata.poa.core;

import java.nio.charset.StandardCharsets;

public class Transaction {
  private final String txId;
  private final String from;
  private final String to;
  private final double amount;
  private final long nonce;
  private final String memo;

  public Transaction(String from, String to, double amount, long nonce, String memo) {
    this.from = from; this.to = to; this.amount = amount; this.nonce = nonce; this.memo = memo;
    this.txId = CryptoUtils.sha256(canonical().getBytes(StandardCharsets.UTF_8));
  }
  public String canonical() {
    return "{\"from\":\""+from+"\",\"to\":\""+to+"\",\"amount\":"+amount+","+
           "\"nonce\":"+nonce+",\"memo\":"+(memo==null?"null":"\""+memo+"\"")+"}";
  }
  // getters
  public String getTxId(){ return txId; }
  public String getFrom(){ return from; }
  public String getTo(){ return to; }
  public double getAmount(){ return amount; }
  public long getNonce(){ return nonce; }
  public String getMemo(){ return memo; }
}


package com.creata.poa.core;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Block {
  private final int index;
  private final long timestamp;
  private final String previousHash;
  private final List<Transaction> transactions;
  private final String merkleRoot;

  private String authorizer;          // "creata"
  private String authoritySignature;  // HMAC على headerWithoutSignature
  private String hash;                // SHA256(headerWithSignature)

  public Block(int index, String previousHash, List<Transaction> txs) {
    this.index = index;
    this.timestamp = Instant.now().getEpochSecond();
    this.previousHash = previousHash;
    this.transactions = Collections.unmodifiableList(new ArrayList<>(txs));
    List<String> txHashes = new ArrayList<>();
    for (Transaction t : txs) txHashes.add(t.getTxId());
    this.merkleRoot = CryptoUtils.merkleRoot(txHashes);
  }

  public String headerWithoutSignature() {
    StringBuilder txs = new StringBuilder();
    for (int i=0;i<transactions.size();i++) {
      if (i>0) txs.append(",");
      txs.append(transactions.get(i).canonical());
    }
    return "{"
      + "\"index\":"+index+","
      + "\"timestamp\":"+timestamp+","
      + "\"previousHash\":\""+previousHash+"\","
      + "\"transactions\":["+txs+"],"
      + "\"merkleRoot\":\""+merkleRoot+"\""
      + "}";
  }
  public String headerWithSignature() {
    return "{"
      + "\"index\":"+index+","
      + "\"timestamp\":"+timestamp+","
      + "\"previousHash\":\""+previousHash+"\","
      + "\"transactions\":[...],"
      + "\"merkleRoot\":\""+merkleRoot+"\","
      + "\"authorizer\":\""+authorizer+"\","
      + "\"authoritySignature\":\""+authoritySignature+"\""
      + "}";
  }

  // setters (used when sealing)
  public void setAuthorizer(String a){ this.authorizer=a; }
  public void setAuthoritySignature(String s){ this.authoritySignature=s; }
  public void setHash(String h){ this.hash=h; }

  // getters
  public int getIndex(){ return index; }
  public long getTimestamp(){ return timestamp; }
  public String getPreviousHash(){ return previousHash; }
  public List<Transaction> getTransactions(){ return transactions; }
  public String getMerkleRoot(){ return merkleRoot; }
  public String getAuthorizer(){ return authorizer; }
  public String getAuthoritySignature(){ return authoritySignature; }
  public String getHash(){ return hash; }
}


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


package com.creata.poa.core;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class Blockchain {
  private final CentralAuthority authority;
  private final List<Block> chain = new ArrayList<>();
  private final List<Transaction> pending = new ArrayList<>();

  public Blockchain(CentralAuthority authority) {
    this.authority = authority;
    createGenesis();
  }

  private void createGenesis() {
    Transaction gtx = new Transaction("__genesis__", authority.name(), 0.0, 0, "genesis");
    Block g = new Block(0, "0".repeat(64), List.of(gtx));
    sealBlock(g);
    chain.add(g);
  }

  private void sealBlock(Block b) {
    b.setAuthorizer(authority.name());
    b.setAuthoritySignature(authority.sign(b.headerWithoutSignature()));
    b.setHash(CryptoUtils.sha256(b.headerWithSignature().getBytes(StandardCharsets.UTF_8)));
  }

  public Transaction addTransaction(String from, String to, double amount, long nonce, String memo) {
    Transaction t = new Transaction(from, to, amount, nonce, memo);
    pending.add(t); return t;
  }

  public Block sealPending(String rewardAddress) {
    pending.add(new Transaction("__system__", rewardAddress, 0.01, 0, "reward"));
    Block b = new Block(chain.size(), chain.get(chain.size()-1).getHash(), pending);
    pending.clear();
    sealBlock(b); chain.add(b); return b;
  }

  public boolean isValid() {
    if (chain.isEmpty()) return false;
    for (int i=1;i<chain.size();i++){
      Block prev = chain.get(i-1), cur = chain.get(i);
      if (!Objects.equals(cur.getPreviousHash(), prev.getHash())) return false;
      if (!authority.verify(cur)) return false;
      List<String> txHashes = new ArrayList<>();
      for (Transaction t : cur.getTransactions()) txHashes.add(t.getTxId());
      if (!Objects.equals(CryptoUtils.merkleRoot(txHashes), cur.getMerkleRoot())) return false;
    }
    return true;
  }

  public double getBalance(String address){
    double bal=0;
    for (Block b: chain) for (Transaction t: b.getTransactions()){
      if (address.equals(t.getFrom())) bal -= t.getAmount();
      if (address.equals(t.getTo()))   bal += t.getAmount();
    }
    return bal;
  }

  public List<Block> getChain(){ return List.copyOf(chain); }
  public List<Transaction> getPending(){ return List.copyOf(pending); }

  // ---------- JSON Persistence ----------
  @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
  public static class State {
    public String authorityName;
    public String difficulty = ""; // احتياطي
    public List<Block> chain;
    public List<Transaction> pending;
  }

  public void save(Path path) throws Exception {
    ObjectMapper om = new ObjectMapper();
    State s = new State();
    s.authorityName = authority.name();
    s.chain = this.chain;
    s.pending = this.pending;
    om.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), s);
  }

  public static Blockchain load(Path path, CentralAuthority authority) throws Exception {
    ObjectMapper om = new ObjectMapper();
    State s = om.readValue(path.toFile(), State.class);
    // إعادة البناء:
    Blockchain bc = new Blockchain(authority);
    bc.chain.clear(); bc.pending.clear();
    bc.chain.addAll(s.chain);
    bc.pending.addAll(s.pending);
    // تحقق سريع بالتوقيع الحالي:
    if (!bc.isValid()) throw new IllegalStateException("Invalid chain or wrong HMAC key");
    return bc;
  }
}


package com.creata.poa.api;

import com.creata.poa.core.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/")
public class BlockchainController {

  private CentralAuthority authority;
  private Blockchain bc;

  public BlockchainController() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    this.authority = new CentralAuthority("creata", key);
    this.bc = new Blockchain(authority);
  }

  // ------ Chain & Balances ------
  @GetMapping("chain")
  public Map<String,Object> chain(){
    return Map.of(
      "authority", authority.name(),
      "valid", bc.isValid(),
      "chain", bc.getChain(),
      "pending", bc.getPending()
    );
  }

  @GetMapping("balance/{addr}")
  public Map<String,Object> balance(@PathVariable String addr){
    return Map.of("address", addr, "balance", bc.getBalance(addr));
  }

  // ------ Transactions ------
  @PostMapping("tx")
  public ResponseEntity<?> addTx(@RequestBody Map<String,Object> body){
    String from = (String) body.get("from");
    String to = (String) body.get("to");
    double amount = Double.parseDouble(body.get("amount").toString());
    long nonce = Long.parseLong(body.get("nonce").toString());
    String memo = body.get("memo")==null?null:body.get("memo").toString();
    Transaction t = bc.addTransaction(from, to, amount, nonce, memo);
    return ResponseEntity.ok(Map.of("txId", t.getTxId()));
  }

  @PostMapping("seal")
  public ResponseEntity<?> seal(@RequestBody Map<String,Object> body){
    String reward = (String) body.getOrDefault("rewardAddress","miner");
    Block b = bc.sealPending(reward);
    return ResponseEntity.ok(Map.of("index", b.getIndex(), "hash", b.getHash()));
  }

  // ------ Persistence ------
  @PostMapping("save")
  public ResponseEntity<?> save(@RequestBody Map<String,Object> body) {
    try {
      String path = (String) body.getOrDefault("path", "chain_state.json");
      bc.save(Path.of(path));
      return ResponseEntity.ok(Map.of("saved", true, "path", path));
    } catch (Exception e){
      return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
  }

  @PostMapping("load")
  public ResponseEntity<?> load(@RequestBody Map<String,Object> body) {
    try {
      String path = (String) body.getOrDefault("path", "chain_state.json");
      this.bc = Blockchain.load(Path.of(path), this.authority);
      return ResponseEntity.ok(Map.of("loaded", true, "path", path, "valid", bc.isValid()));
    } catch (Exception e){
      return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
  }

  // ------ HMAC Key export/import ------
  @GetMapping("key/export")
  public Map<String,Object> exportKey(){
    return Map.of("authority", authority.name(),
                  "hmacKeyBase64", Base64.getEncoder().encodeToString(authority.key()));
  }

  @PostMapping("key/import")
  public ResponseEntity<?> importKey(@RequestBody Map<String,String> body){
    try {
      byte[] k = Base64.getDecoder().decode(body.get("hmacKeyBase64"));
      authority.importKey(k);
      // بعد تبديل المفتاح، تحقق من السلسلة الحالية (قد تفشل إن لم يكن نفس المفتاح)
      boolean ok = bc.isValid();
      return ResponseEntity.ok(Map.of("imported", true, "validWithNewKey", ok));
    } catch (Exception e){
      return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
  }
}
