control "xccdf_mil.disa.stig_rule_SV-86685r2_rule" do
  title "The Red Hat Enterprise Linux operating system must use a separate file system for /var."
  desc  "
    Vulnerability Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
    
    Documentable: false
    
  "
  impact 0.1
  describe mount("/var") do
    it { should be_mounted }
  end
end
