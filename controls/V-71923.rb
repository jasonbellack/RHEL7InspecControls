control "xccdf_mil.disa.stig_rule_SV-86547r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords."
  desc  "
    Vulnerability Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/libuser.conf") do
    its("content") { should match(/^[\s]*crypt_style[\s]+=[\s]+(\S+)[\s]*$/) }
  end
  file("/etc/libuser.conf").content.to_s.scan(/^[\s]*crypt_style[\s]+=[\s]+(\S+)[\s]*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^[Ss][Hh][Aa]512$/) }
    end
  end
end
