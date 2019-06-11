control "xccdf_mil.disa.stig_rule_SV-86707r2_rule" do
  title "The Red Hat Enterprise Linux operating system must off-load audit records onto a different system or media from the system being audited."
  desc  "
    Vulnerability Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
    
    Off-loading is a common process in information systems with limited audit storage capacity.
    
    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/audisp/audisp-remote.conf") do
    its("content") { should match(/^[ ]*remote_server[ ]+=[ ]+(.*)/mi) }
  end
  file("/etc/audisp/audisp-remote.conf").content.to_s.scan(/^[ ]*remote_server[ ]+=[ ]+(.*)/mi).flatten.each do |entry|
    describe entry do
      it { should match(/^.+$/) }
    end
  end
end
