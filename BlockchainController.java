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
