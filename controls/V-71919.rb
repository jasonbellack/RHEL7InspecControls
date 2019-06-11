control "xccdf_mil.disa.stig_rule_SV-86543r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords."
  desc  "
    Vulnerability Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/) }
  end
  describe file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten do
    its("length") { should >= 1 }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))sha512(?:\s|$)/) }
    end
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should_not match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))(?:md5|sha256|bigcrypt|blowfish)(?:\s|$)/) }
    end
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/) }
  end
  describe file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten do
    its("length") { should >= 1 }
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))sha512(?:\s|$)/) }
    end
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should_not match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))(?:md5|sha256|bigcrypt|blowfish)(?:\s|$)/) }
    end
  end
end
