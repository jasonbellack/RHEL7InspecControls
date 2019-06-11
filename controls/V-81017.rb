control "xccdf_mil.disa.stig_rule_SV-95729r1_rule" do
  title "The Red Hat Enterprise Linux operating system must configure the au-remote plugin to off-load audit logs using the audisp-remote daemon."
  desc  "
    Vulnerability Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    Without the configuration of the 'au-remote' plugin, the audisp-remote daemon will not off load the logs from the system being audited.

    Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

    Documentable: false

  "
  impact 1.0
  describe file("/etc/audisp/plugins.d/au-remote.conf") do
    it { should exist }
    its("content") { should match(/^.*direction[\s]=[\s]out[\n]path[\s]=[\s]\/sbin\/audisp-remote[\n]type[\s]=[\s]always.*$/) }
  end
end
