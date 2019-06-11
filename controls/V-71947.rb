control "xccdf_mil.disa.stig_rule_SV-86571r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation."
  desc  "
    Vulnerability Discussion: Without re-authentication, users may access resources or perform tasks for which they do not have authorization.
    
    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
    
    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/sudoers") do
    its("content") { should_not match(/^(?!#).*[\s]+NOPASSWD[\s]*\:.*$/) }
  end
  files = command("find /etc/sudoers.d -type f -regex .\\*/\\^.\\*\\$").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content =~ /^(?!#).*[\s]+NOPASSWD[\s]*\:.*$/ } do
    it { should be_empty }
  end
end
