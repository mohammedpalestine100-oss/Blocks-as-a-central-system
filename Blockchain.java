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
