control "xccdf_mil.disa.stig_rule_SV-95731r1_rule" do
  title "The Red Hat Enterprise Linux operating system must take appropriate action when the audisp-remote buffer is full."
  desc  "
    Vulnerability Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    When the remote buffer is full, audit logs will not be collected and sent to the central log server.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

    Documentable: false

  "
  impact 1.0
  describe file("/etc/audisp/audispd.conf") do
    it { should exist }
    its("content") { should match(/^.*overflow_action[\s]=[\s][Ss][Yy][Ss][Ll][Oo][Gg].*$/) }
  end
end
