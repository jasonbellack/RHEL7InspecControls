control "xccdf_mil.disa.stig_rule_SV-86549r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 24 hours/1 day minimum lifetime."
  desc  "
    Vulnerability Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MIN_DAYS\s+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 1 }
    end
  end
end
