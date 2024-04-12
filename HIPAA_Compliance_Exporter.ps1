# Define file paths and import settings file
$current_dir = $PSScriptRoot
$settings_obj = Get-Content -Path "$current_dir\settings.json" | ConvertFrom-Json
$server_drive = $settings_obj.server_drive
$server_data_dir = $settings_obj.server_data_dir
$data_dir = $server_drive + "\" + $server_data_dir
$favicon_path = $current_dir + "\favicon.ico"

# Define outfile name
Function Set-FileName {
    $date = Get-Date -Format "yyyyMMdd-HHmm"
    $new_outfile = ($browse_dialog.SelectedPath) + "\" + ($org_menu.SelectedItem) + "_DeviceExport_" + ($date) + ".csv"
    $new_reffile = $data_dir + "\" + ($org_menu.SelectedItem) + "_DeviceExport_" + ($date) + ".csv"
    return $new_outfile, $new_reffile
}

# Export-Data is the entire call to Ninja's API and export of data, including
# organizing the data and writing it to a .csv
Function Export-Data {    
    # URLs
    $url_prefix = "https://app.ninjarmm.com/api/v2"
    $org_url = "$url_prefix/organizations"
    $device_url = "$url_prefix/devices-detailed"
    $location_url = "$url_prefix/locations"
    $av_url = "$url_prefix/queries/antivirus-status"
    $cust_field_url = "$url_prefix/queries/custom-fields?pageSize=10000"
    $net_url = "$url_prefix/queries/network-interfaces"
    
    # API body
    $body = @{
        grant_type = "client_credentials"
        client_id = $username.Text
        client_secret = $password.Text
        redirect_uri = "https://localhost"
        scope = "monitoring"
    }
    
    # API authentication
    $API_AuthHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $API_AuthHeaders.Add("accept", 'application/json')
    $API_AuthHeaders.Add("Content-Type", 'application/x-www-form-urlencoded')
    
    $auth_token = Invoke-RestMethod -Uri "https://app.ninjarmm.com/oauth/token" -Method POST -Headers $API_AuthHeaders -Body $body
    $access_token = $auth_token | Select-Object -ExpandProperty 'access_token' -EA 0
    
    # API headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("accept", 'application/json')
    $headers.Add("Authorization", "Bearer $access_token")
    
    # retrieve device details information
    $org_details = Invoke-RestMethod -Uri $org_url -Method GET -Headers $headers
    $location_details = Invoke-RestMethod -Uri $location_url -Method GET -Headers $headers
    $device_details = Invoke-RestMethod -Uri $device_url -Method GET -Headers $headers
    $av_details = Invoke-RestMethod -Uri $av_url -Method GET -Headers $headers
    $cust_field_details = Invoke-RestMethod -Uri $cust_field_url -method GET -Headers $headers
    $net_details = Invoke-RestMethod -Uri $net_url -Method GET -Headers $headers
    
    $user_org_id = $org_details | Where-Object -Property name -eq $org_menu.SelectedItem | Select-Object -ExpandProperty id
    $user_locations = $location_details | Where-Object -Property organizationId -eq $user_org_id
    $user_devices = $device_details | Where-Object -Property organizationId -eq $user_org_id
    
    $objects = @()
    foreach ($device in $user_devices) {
        # Get OS (Windows or Mac)
        $serial_num = ""
        if ($device.nodeClass -eq "MAC") {  # If device is MacOS
            $serial_num = $device.system.serialNumber
        } else {
            $serial_num = $device.system.biosSerialNumber
        }

        # Set device type to custom text
        $device_type_output = ""
        # Windows server
        if ($device.nodeClass -eq "WINDOWS_SERVER") {
            $device_type_output = "Server"
        # Windows Workstation
        } elseif ($device.nodeClass -eq "WINDOWS_WORKSTATION") {
            if ($device.system.chassisType -eq "DESKTOP") {
                $device_type_output = "Desktop Computer"
            } else {
                $device_type_output = "Laptop"
            }
        # Mac Server
        } elseif ($device.nodeClass -eq "MAC_SERVER") {
            $device_type_output = "Server"
        # Mac Workstation
        } elseif ($device.nodeClass -eq "MAC") {
            if ($device.system.chassisType -eq "DESKTOP") {
                $device_type_output = "Desktop Computer"
            } else {
                $device_type_output = "Laptop"
            }
        # Linux
        } elseif ($device.nodeClass -Match "LINUX") {
            $device_type_output = "Server"
        }
        
        # Get location name
        $location_name = $user_locations | Where-Object -Property id -eq $device.locationId | Select-Object -ExpandProperty name
        $location_name = $location_name.Split("(")  # This is only needed because location format is "Random City (RAND)"
        $location_name = $location_name[0]  # This is only needed because location format is "Random City (RAND)"

        # Get AV
        $has_av = "Yes"
        if ($device.nodeClass -eq "WINDOWS_SERVER") {
            $av = $cust_field_details.results `
                | Where-Object -Property deviceId -eq $device.id `
                | Select-Object -ExpandProperty fields `
                | Select-Object -ExpandProperty av_present -ErrorAction SilentlyContinue
        } else {
            $av = $av_details.results `
                | Where-Object -Property deviceId -eq $device.id `
                | Select-Object -ExpandProperty productName
            if ($av -eq "NONE") {
                $has_av = "No"
            }
        }
    
        # Get IP Address
        $ip = $net_details.results | Where-Object -Property deviceId -eq $device.id | Select-Object -ExpandProperty ipAddress
        $new_ip = @()
        if ($ip.Count -gt 1) {
            foreach ($z in $ip) {
                if (($z -NotMatch ":") -And ($z -NotMatch "169.254.")) {
                    $new_ip += $z
                }
            }
            if ($new_ip -gt 1) {
                $new_ip = $new_ip[-1]
            }
        } else {
            $new_ip = $ip
        }

        # Get Bitlocker/FileVault status
        $encryption = "Yes"
        if ($device.nodeClass -Match "WINDOWS_") {
            Try {
                $encryption = $cust_field_details.results `
                    | Where-Object -Property deviceId -eq $device.id `
                    | Select-Object -ExpandProperty fields `
                    | Select-Object -ExpandProperty bitlocker -ErrorAction SilentlyContinue
            } catch {
                # Custom field has not been filled in yet.
                $encryption = ""
            }
        } elseif ($device.nodeClass -eq "MAC") {
            Try {
                $encryption = $cust_field_details.results `
                    | Where-Object -Property deviceId -eq $device.id `
                    | Select-Object -ExpandProperty fields `
                    | Select-Object -ExpandProperty filevault -ErrorAction SilentlyContinue
            } catch {
                # Custom field has not been filled in yet.
                $encryption = ""
            }
        } elseif ($device.nodeClass -eq "LINUX") {
            $encryption = "No"
        }
    
        $data = [pscustomobject]@{
            "DeviceName" = $device.systemName
            "DeviceType" = $device_type_output
            "Activated" = $null #Activated
            "Deactivated" = $null #Deactivated
            "AssetTag" = $null #Asset Tag
            "Model" = ($device.system.manufacturer) + " " + ($device.system.model)
            "SerialNumber" = $serial_num
            "PhysicalLocation" = $location_name
            "UserAssigned" = $device.lastLoggedInUser
            "LastIPAddress" = ($new_ip | Out-String).Trim()
            "EPHI" = $null #Stores/Touches ePHI
            "EndPointProtection" = $has_av #($new_av | Out-String).Trim()
            "Encryption" = $encryption #Encryption
            "RiskRating" = $null #Risk Rating
            "Notes" = $null #Notes
        }
        $objects += $data
    }
    return $objects
}

Function Test-ApiCreds {
    # URL
    $url = "https://app.ninjarmm.com/api/v2/organizations"

    # Headers and authentication
    # API body
    $body = @{
        grant_type = "client_credentials"
        client_id = $username.Text
        client_secret = $password.Text
        redirect_uri = "https://localhost"
        scope = "monitoring"
    }
    
    # API authentication
    $API_AuthHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $API_AuthHeaders.Add("accept", 'application/json')
    $API_AuthHeaders.Add("Content-Type", 'application/x-www-form-urlencoded')
    
    $auth_token = $null
    $access_token = $null
    try {
        $auth_token = Invoke-RestMethod -Uri "https://app.ninjarmm.com/oauth/token" -Method POST -Headers $API_AuthHeaders -Body $body
        $access_token = $auth_token | Select-Object -ExpandProperty 'access_token' -EA 0
    } catch {
        return 1
    }
    
    # API headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("accept", 'application/json')
    $headers.Add("Authorization", "Bearer $access_token")

    try {
        
        Invoke-WebRequest -Uri $url -Method GET -Headers $headers
        return 0
    } catch {
        return 1
    }
}

Function Test-ServerDirectory($path) {
    if (Test-Path -Path $path) {
        return 0
    } else {
        return 1
    }
}

Function Test-FolderPermissions($path) {
    # Attempt to create file
    try {
        New-Item -Path $path | Out-Null
        if (Test-Path -Path $path) {
            return 0
        } else {
            return 1
        }
    } catch {
        return 1
    }
}

Function Test-DataExport($path) {
    # Test that the file exists and that it's over 8 bytes.
    # Make sure it contains more than just a couple of random characters.
    if ((Test-Path -Path $path) -and ((Get-Item -Path $path).Length -ge 8)) {
        return 0
    } else {
        return 1
    }
}

Function Compare-Changes {
    # ONLY RETURN NEW DEVICES
    # Get previous data
    $ref_str = $org_menu.SelectedItem + "*"
    $ref_file = Get-ChildItem -Path $data_dir `
        | Sort-Object LastWriteTime `
        | Where-Object -Property Name -Like $ref_str `
        | Select-Object -Last 1 # -ExpandProperty FullName
    if (($ref_file.FullName).Count -eq 0) {
        $output_field.AppendText("No previous data for organizaton exists.`r`n")
        $output_field.AppendText("Exporting full list of devices...`r`n`r`n")
        $new_data | Export-Csv -Path $outfile -NoTypeInformation -Force
        return 0
    } else {
        $ref_data = Import-Csv -Path $ref_file.FullName
        $changes = Compare-Object -ReferenceObject $ref_data -DifferenceObject $new_data `
            | Where-Object -Property SideIndicator -eq "=>" `
            | Select-Object -ExpandProperty InputObject

        # Test for changes since last time an export was ran.
        # If no changes, write to output_field.
        # Else, export data to chosen location.
        if ($changes.Count -eq 0) {
            $output_field.AppendText("No changes detected since previous export.`r`n")
            $output_field.AppendText("Nothing to export.`r`n`r`n")
            return 1
        } else {
            $changes | Export-Csv -Path $outfile -NoTypeInformation -Force
            return 2
        }
    }
}

Function Prompt-User {
    # Yes/No popup asking if user would like to save new data as the next reference file
    $title = "Save?"
    $msg = "Would you like to save the newest data as the new baseline? (Recommend 'Yes' unless you have a reason to discard today's data)"
    $type = 'YesNo'
    $img = 'Question'
    $result = [System.Windows.Forms.MessageBox]::Show($msg,$title,$type,$img)
    return $result
}

# Save new data to be used as a reference in the future
Function Write-NewReferenceFile {
    $new_data | Export-Csv -Path $new_reference_file -NoTypeInformation -Force
    Set-ItemProperty -Path $new_reference_file -Name IsReadOnly -Value $true
    if (Test-Path -Path $new_reference_file) {
        $output_field.AppendText("New baseline saved successfully.`r`n")
    } else {
        $output_field.AppendText("There was a problem saving new baseline.`r`n")
    }
}

# Import assembly
Add-Type -AssemblyName System.Windows.Forms

# Create window
$gui = New-Object System.Windows.Forms.Form
$gui.ClientSize = "600,700"
$gui.Text = "HIPAA Compliance Export"
$gui.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($favicon_path)
$gui.BackColor = "#ffffff"

# Instruct user to enter credentials
$cred_inst = New-Object System.Windows.Forms.Label
$cred_inst.Text = "Enter your Ninja API credentials below:"
$cred_inst.AutoSize = $true
$cred_inst.Location = New-Object System.Drawing.Point(20,20)

# API Username
$username = New-Object System.Windows.Forms.TextBox
$username.Text = "NinjaRMM API Access Key"
$username.Width = 560
$username.Location = New-Object System.Drawing.Point(20,50)

# API Password
$password = New-Object System.Windows.Forms.TextBox
$password.Text = "NinjaRMM API Secret Key"
$password.Width = 560
$password.Location = New-Object System.Drawing.Point(20,80)

# Line Break 1
$line_break_1 = New-Object System.Windows.Forms.Label
$line_break_1.Text = "______________________________"
$line_break_1.AutoSize = $true
$line_break_1.Location = New-Object System.Drawing.Point(20,110)

# Instruct user to choose an organization
$org_inst = New-Object System.Windows.Forms.Label
$org_inst.Text = "Choose an organization."
$org_inst.AutoSize = $true
$org_inst.Location = New-Object System.Drawing.Point(20,150)

# Drop-down menu containing all organizations
$org_menu = New-Object System.Windows.Forms.ComboBox
$org_menu.Text = "Select..."
$org_menu.Width = 90
$org_menu.Location = New-Object System.Drawing.Point(40,180)
ForEach ($o in $settings_obj.orgs) {
    $org_menu.Items.Add($o) | Out-Null
}

# Warn if no org selected
$org_warn = New-Object System.Windows.Forms.Label
$org_warn.Width = 200
$org_warn.Location = New-Object System.Drawing.Point(150,185)

# Line Break 2
$line_break_2 = New-Object System.Windows.Forms.Label
$line_break_2.Text = "______________________________"
$line_break_2.AutoSize = $true
$line_break_2.Location = New-Object System.Drawing.Point(20,210)

# Instruct user to browse for the output folder
$browse_inst = New-Object System.Windows.Forms.Label
$browse_inst.Text = "Click 'Browse' to select the folder you'd like to save the export to."
$browse_inst.AutoSize = $true
$browse_inst.Location = New-Object System.Drawing.Point(20,250)

# Browse button
$browse_button = New-Object System.Windows.Forms.Button
$browse_button.BackColor = "$eeeeee"
$browse_button.Text = "Browse"
$browse_button.Width = 90
$browse_button.Height = 30
$browse_button.Location = New-Object System.Drawing.Point(40,280)

# Folder location display field
$dir_field = New-Object System.Windows.Forms.TextBox
$dir_field.ReadOnly = $true
$dir_field.Width = 430
$dir_field.Location = New-Object System.Drawing.Point(150,285)

# Folder browse dialog
$browse_dialog = New-Object System.Windows.Forms.FolderBrowserDialog

# Define browse button action
### Open folder selection screen
$browse_button.Add_Click({
    $browse_dialog.ShowDialog()
    $dir_field.Text = ($browse_dialog.SelectedPath) + "\XYZ_DeviceExport_xxxxxxxx-xxxx.csv"
    $dir_field.ForeColor = "Green"
    $dir_field.BackColor = "White"
})

# Line Break 3
$line_break_3 = New-Object System.Windows.Forms.Label
$line_break_3.Text = "______________________________"
$line_break_3.AutoSize = $true
$line_break_3.Location = New-Object System.Drawing.Point(20,310)

# Instruct user to click Export Data when ready
$go_inst = New-Object System.Windows.Forms.Label
$go_inst.Text = "Click 'Export Data' after doing the above steps."
$go_inst.AutoSize = $true
$go_inst.Location = New-Object System.Drawing.Point(20,350)

# Export button
$go_button = New-Object System.Windows.Forms.Button
$go_button.BackColor = "$eeeeee"
$go_button.Text = "Export Data"
$go_button.Width = 90
$go_button.Height = 30
$go_button.Location = New-Object System.Drawing.Point(40,380)

# Field where messages are displayed to the user
$output_field = New-Object System.Windows.Forms.TextBox
$output_field.ReadOnly = $true
$output_field.Width = 560
$output_field.Height = 260
$output_field.Multiline = $true
$output_field.Text = "Ready."
$output_field.Location = New-Object System.Drawing.Point(20,420)

# Define go button action
### Call API and export data to .csv at selected location
$go_button.Add_Click({
    # Test if org menu and directory choice have valid item selected
    if (($org_menu.SelectedItem -eq $null) -or (($browse_dialog.SelectedPath).Length -eq 0)) {
        # Both have no data
        if (($org_menu.SelectedItem -eq $null) -and (($browse_dialog.SelectedPath).Length -eq 0)) {
            $org_warn.Text = "Please select an organization."
            $org_warn.ForeColor = "Red"
            $dir_field.BackColor = "#E57373"
            $dir_field.Text = "Please select a folder."
        } elseif ($org_menu.SelectedItem -eq $null) {
            # org menu has no data
            $org_warn.Text = "Please select an organization."
            $org_warn.ForeColor = "Red"
        } elseif (($browse_dialog.SelectedPath).Length -eq 0) {
            # directory choice has no data
            $dir_field.Text = "Please select a folder."
            $dir_field.BackColor = "#E57373"
        }
    } else {
        # Write confirmation messages
        $org_warn.Text = "Organization selected"
        $org_warn.ForeColor = "Green"
        $dir_field.Text = ($browse_dialog.SelectedPath) + "\XYZ_DeviceExport_xxxxxxxx-xxxx.csv"
        $dir_field.ForeColor = "Green"

        # Test if can reach the server directory
        $output_field.Text = "Testing server access...`r`n"
        if ((Test-ServerDirectory($data_dir)) -eq 1) {
            $output_field.AppendText("Unable to reach server. Check you have access to '$data_dir'.`r`n`r`n")
        } else {
            $output_field.AppendText("Server access ok.`r`n`r`n")
            # Test credentials
            $output_field.AppendText("Testing Credentials...`r`n")
            $test_creds = Test-ApiCreds
            if ($test_creds -eq "0") {
                $output_field.AppendText("Credentials ok.`r`n`r`n")

                # Test folder write permissions
                # Create filename
                $outfile, $new_reference_file = Set-FileName

                $output_field.AppendText("Testing folder write access...`r`n")
                if ((Test-FolderPermissions($outfile)) -eq 0) {
                    $output_field.AppendText("Folder access ok.`r`n`r`n")
                
                    # Attempt to export data
                    $output_field.AppendText("Processing API requests and exporting data.`r`n")
                    $output_field.AppendText("This will take a minute. Please wait...`r`n`r`n")
                    #Export-Data($outfile)
                    $new_data = Export-Data

                    $compare = Compare-Changes
                    if (($compare -eq 0) -or ($compare -eq 2)) {

                        # Test if data export was successful
                        $test_export = Test-DataExport($outfile)
                        if ($test_export -eq 0) {
                            $output_field.AppendText("Data export complete.`r`n")
                            $output_field.AppendText("File resides at $outfile.`r`n`r`n")
                        } else {
                            #$err_str = $test_export | Out-String
                            #$output_field.AppendText($err_str)
                            $output_field.AppendText("Data export failed.`r`n")
                            $output_field.AppendText("File doesn't exist or data is too small (< 8 bytes).")
                        }

                        # As user if they want to save new data as the new baseline
                        $save_prompt = Prompt-User
                        if ($save_prompt -eq 6) {
                            Write-NewReferenceFile
                        }
                    }   
                } else {
                    $output_field.AppendText("Do not have permission to create file at " + ($browse_dialog.SelectedPath | Out-String))
                    $output_field.AppendText("Please verify you have write permissions and that security software is not blocking it.`r`n")
                }
            } else {
                $output_field.AppendText("Unable to authenticate with Ninja API.`r`n")
                $output_field.AppendText("Please check credentials and internet connection.`r`n")
            }
        }
    }
})

# Choose what objects to display to GUI
$gui.Controls.AddRange(
    @(
        $cred_inst,
        $username,
        $password,
        $line_break_1,
        $org_inst,
        $org_menu,
        $org_warn,
        $line_break_2,
        $browse_inst,
        $browse_button,
        $dir_field,
        $line_break_3,
        $go_inst,
        $go_button,
        $output_field
    )
)

# Display GUI
[void]$gui.ShowDialog()








###### SIGNATURE ######
