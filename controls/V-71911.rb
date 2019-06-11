control "xccdf_mil.disa.stig_rule_SV-86535r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of eight of the total number of characters must be changed."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^.*difok[\s]*=[\s]*(\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^.*difok[\s]*=[\s]*(\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 8 }
    end
  end
end
