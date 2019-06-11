control "xccdf_mil.disa.stig_rule_SV-86637r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory."
  desc  "
    Vulnerability Discussion: If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*CREATE_HOME\s+(\S+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*CREATE_HOME\s+(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end
