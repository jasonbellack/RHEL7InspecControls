control "xccdf_mil.disa.stig_rule_SV-86719r6_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all executions of privileged functions."
  desc  "
    Vulnerability Discussion: Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.    
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/audit/rules.d/audit.rules") do
    it { should exist }
  end
  describe file("/etc/audit/rules.d/audit.rules") do
    its("content") { should match('-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid') }
    its("content") { should match('-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid') }   
 end
end
