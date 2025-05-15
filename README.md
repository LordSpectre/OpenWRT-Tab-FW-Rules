<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LuCI Firewall Tabs</title>
</head>
<body>

    <h2>LuCI Firewall Tabs Enhancement</h2>

    <p>Following my first attempt to improve the LuCI interface so that Firewall rules would be displayed in separate tabs based on their originating zone: <a href="https://github.com/LordSpectre/OpenWRT-Viewer">https://github.com/LordSpectre/OpenWRT-Viewer</a>, this is my second attempt, implemented directly in LuCI without using an external server.</p>

    <h3>Package Contents</h3>

    <ul>
        <li><strong>firewalltabs_view.js</strong>  
            <p>This JavaScript file adds a tab next to the existing Firewall rules tab and is read-only. It simply collects all firewall rules and categorizes them into separate tabs, displaying rules specific to their originating zone. No modifications can be made here—it's purely for viewing.</p>
        </li>
        <li><strong>firewalltabs-full.js</strong>  
            <p>Here, I attempted to reproduce the entire "Firewall Rules" tab. Like the previous JavaScript file, it takes all firewall rules and organizes them into separate tabs based on their originating zone.</p>
            <p>In this version, users can modify, delete, or create new rules just like in the original tab.</p>
            <p><strong>WARNING:</strong> Unfortunately, I haven't been able to fully resolve a minor issue related to adding and editing rules. For example, when a new rule is added, it will not immediately display all its parameters in the GUI. The page needs to be refreshed or, more simply, the user needs to click on the tab again.</p>
            <p>This is a LuCI refresh issue that I have yet to address.</p>
            <p>Other than that, the interface functions perfectly: rules can be added, modified, or deleted as expected—it’s purely a visual matter.</p>
            <p>I hope to resolve this issue in the coming days, and any contributions are welcome.</p>
        </li>
    </ul>

    <h3>Installation Instructions</h3>

    <p>Since there are only two files, I did not create an IPK package. Instead, the files need to be copied manually to their respective directories.</p>

    <ol>
        <li>Choose the view you prefer (<code>firewalltabs-full.js</code> or <code>firewalltabs_view.js</code>) and rename the <code>.js</code> file to <code>firewalltabs.js</code>.</li>
        <li>Copy the two files exactly to these locations:  
            <ul>
                <li><code>/usr/share/luci/menu.d/luci-app-firewall-rules.json</code></li>
                <li><code>/www/luci-static/resources/view/firewall/firewalltabs.js</code></li>
            </ul>
        </li>
        <li>Clear the cache on OpenWRT and in your browser:
            <ul>
                <li>Run the following command on OpenWRT:  
                    <code>root@OpenWRT # rm -f /tmp/*cach*</code></li>
                <li>And on the browser: Press <code>CTRL+SHIFT+R</code> or <code>CTRL+F5</code>.</li>
            </ul>
        </li>
    </ol>

    <p>The new tab will appear under <strong>Network → Firewall</strong>, as shown in the image below.</p>

    <img src="https://cover.laforestaincantata.org/i/00f6d64b-dabe-4300-ab3f-50fe84d870c3.png" alt="Firewall Tabs Screenshot">

</body>
</html>
