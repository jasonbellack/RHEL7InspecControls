control "xccdf_mil.disa.stig_rule_SV-86861r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements."
  desc  "
    Vulnerability Discussion: Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.
    
    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
    
    Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("ClientAliveInterval") { should_not be_nil }
    its("ClientAliveInterval") { should cmp <= 600 }
    its("ClientAliveInterval") { should cmp > 0 }
  end
end
