control "xccdf_mil.disa.stig_rule_SV-87811r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \"pwquality\" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^[ \t]*password[ \t]+required[ \t]+pam_pwquality\.so(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]+))retry=([0-9]+)(?:\s|$)/) }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^[ \t]*password[ \t]+required[ \t]+pam_pwquality\.so(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]+))retry=([0-9]+)(?:\s|$)/).flatten.each do |entry|
    describe entry do
      it { should match(/^[123]$/) }
    end
  end
end
