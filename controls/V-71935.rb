control "xccdf_mil.disa.stig_rule_SV-86559r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords are a minimum of 15 characters in length."
  desc  "
    Vulnerability Discussion: The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.
    
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^.*minlen[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^.*minlen[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 15 }
    end
  end
end
