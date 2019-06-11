control "xccdf_mil.disa.stig_rule_SV-86711r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when the audit storage volume is full."
  desc  "
    Vulnerability Discussion: Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/audisp/audisp-remote.conf") do
    its("content") { should match(/^\s*disk_full_action\s+=\s+(\S+)\s*$/mi) }
  end
  file("/etc/audisp/audisp-remote.conf").content.to_s.scan(/^\s*disk_full_action\s+=\s+(\S+)\s*$/mi).flatten.each do |entry|
    describe.one do
      describe entry do
        it { should match(/^[Ss][Yy][Ss][Ll][Oo][Gg]$/) }
      end
      describe entry do
        it { should match(/^[Ss][Ii][Nn][Gg][Ll][Ee]$/) }
      end
      describe entry do
        it { should match(/^[Hh][Aa][Ll][Tt]$/) }
      end
    end
  end
end
