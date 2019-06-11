control "xccdf_mil.disa.stig_rule_SV-86687r6_rule" do
  title "The Red Hat Enterprise Linux operating system must use a separate file system for the system audit data path."
  desc  "
    Vulnerability Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
    
    Documentable: false
    
  "
  impact 0.1
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
  describe file("/etc/fstab") do
    its("content") { should match(/^\S+\s+\/var\/log\/audit\s+/) }
  end
end
