control "xccdf_mil.disa.stig_rule_SV-86557r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords are prohibited from reuse for a minimum of five generations."
  desc  "
    Vulnerability Discussion: Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:sufficient)|(?:required))\s+pam_unix\.so[^#\n\r]*remember=([0-9]*).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[^#\n\r]*remember=([0-9]*).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
  end
  describe.one do
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:sufficient)|(?:required))\s+pam_unix\.so[^#\n\r]*remember=([0-9]*).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[^#\n\r]*remember=([0-9]*).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
  end
end
