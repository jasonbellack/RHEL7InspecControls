control "xccdf_mil.disa.stig_rule_SV-86933r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is a router."
  desc  "
    Vulnerability Discussion: Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^[\s]*net\.ipv4\.ip_forward[\s]*=[\s]*0[\s]*$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.ip_forward[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.ip_forward[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.ip_forward[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should eq 0 }
  end
end
