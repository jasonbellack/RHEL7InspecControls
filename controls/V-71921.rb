control "xccdf_mil.disa.stig_rule_SV-86545r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store only encrypted representations of passwords."
  desc  "
    Vulnerability Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*ENCRYPT_METHOD\s+(\w+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*ENCRYPT_METHOD\s+(\w+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should eq "SHA512" }
    end
  end
end
