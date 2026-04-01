import { useState } from "react";

const call = async (url, method="GET", body) => {
  const res = await fetch(url, {
    method,
    headers: {"Content-Type":"application/json"},
    body: body ? JSON.stringify(body) : undefined
  });
  return res.json();
};

export default function App() {
  const [log, setLog] = useState("");

  const add = (t) => setLog((s) => s + (t.endsWith("\n")? t : t + "\n"));

  const run = async (fn) => {
    add(`> ${fn} ...`);
    let out = {};
    if (fn==="Detect") out = await call("/api/detect");
    if (fn==="CreateFake10MB") out = await call("/api/create-fake-disk","POST",{size_mb:10});
    if (fn==="Clear") out = await call("/api/clear","POST",{});
    if (fn==="CE") out = await call("/api/ce","POST",{operator:"TeamSIH"});
    if (fn==="VerifyClear") out = await call("/api/verify","POST",{method:"clear"});
    if (fn==="VerifyCE") out = await call("/api/verify","POST",{method:"ce"});
    if (fn==="Ledger") out = await call("/api/ledger");
    if (fn==="VerifySignature") out = await call("/api/verify-signature","POST",{});
    add(out.stdout || JSON.stringify(out,null,2));
  };

  return (
    <div style={{fontFamily:"ui-monospace, SFMono-Regular, Menlo, monospace", padding:16}}>
      <h2>UVSO Demo</h2>
      <div style={{display:"grid", gap:8, gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))", marginBottom:12}}>
        <button onClick={()=>run("Detect")}>Detect Storage</button>
        <button onClick={()=>run("CreateFake10MB")}>Create Fake Disk 10MB</button>
        <button onClick={()=>run("Clear")}>Clear (0xFF → 0x00)</button>
        <button onClick={()=>run("CE")}>Cryptographic Erase</button>
        <button onClick={()=>run("VerifyClear")}>Verify + Cert (Clear)</button>
        <button onClick={()=>run("VerifyCE")}>Verify + Cert (CE)</button>
        <button onClick={()=>run("Ledger")}>Show Ledger</button>
        <button onClick={()=>run("VerifySignature")}>Verify Signature</button>
      </div>
      <pre style={{whiteSpace:"pre-wrap", background:"#111", color:"#ddd", padding:12, borderRadius:8, minHeight:280}}>
        {log || "Output will appear here..."}
      </pre>
    </div>
  );
}