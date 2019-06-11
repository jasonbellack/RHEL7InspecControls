control "xccdf_mil.disa.stig_rule_SV-87827r4_rule" do
  title "The Red Hat Enterprise Linux operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages."
  desc  "
    Vulnerability Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    ipv4_all_accept_redirects = file("/etc/sysctl.conf").content.to_s.scan(/^\s*net\.ipv4\.conf\.all\.accept_redirects[\s]*=[\s]*(\d+)\s*$/).flatten
    describe ipv4_all_accept_redirects.reject { |x| x == "0" } do
      it { should be_empty }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.all\.accept_redirects[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.all\.accept_redirects[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.all\.accept_redirects[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
    its("value") { should eq 0 }
  end
end
