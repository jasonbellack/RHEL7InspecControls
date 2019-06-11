control "xccdf_mil.disa.stig_rule_SV-95733r1_rule" do
  title "The Red Hat Enterprise Linux operating system must label all off-loaded audit logs before sending them to the central log server."
  desc  "
    Vulnerability Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

    Documentable: false

  "
  impact 1.0
  describe file("/etc/audisp/audispd.conf") do
    it { should exist }
    its("content") { should match(/^.*name_format[\s]=[\s][Hh][Oo][Ss][Tt][Nn][Aa][Mm][Ee].*$/) }
  end
end
