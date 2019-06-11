control "xccdf_mil.disa.stig_rule_SV-86683r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that a separate file system is used for user home directories (such as /home or an equivalent)."
  desc  "
    Vulnerability Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
    
    Documentable: false
    
  "
  impact 0.1
  describe mount("/home") do
    it { should be_mounted }
  end
end
