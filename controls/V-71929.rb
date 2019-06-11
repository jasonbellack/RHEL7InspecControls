control "xccdf_mil.disa.stig_rule_SV-86553r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime."
  desc  "
    Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MAX_DAYS\s+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end
