<%@ Assembly Name="$SharePoint.Project.AssemblyFullName$" %>
<%@ Import Namespace="Microsoft.SharePoint.ApplicationPages" %>
<%@ Register TagPrefix="SharePoint" Namespace="Microsoft.SharePoint.WebControls"
    Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register TagPrefix="Utilities" Namespace="Microsoft.SharePoint.Utilities" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register TagPrefix="asp" Namespace="System.Web.UI" Assembly="System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" %>
<%@ Import Namespace="Microsoft.SharePoint" %>
<%@ Assembly Name="Microsoft.Web.CommandUI, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>

<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Settings.aspx.cs" Inherits="Auth0.ClaimsProvider.AdminWeb.Settings"
    MasterPageFile="~/_admin/admin.master" %>

<%@ Register TagPrefix="wssuc" TagName="InputFormSection" Src="~/_controltemplates/InputFormSection.ascx" %>
<%@ Register TagPrefix="wssuc" TagName="InputFormControl" Src="~/_controltemplates/InputFormControl.ascx" %>
<%@ Register TagPrefix="wssuc" TagName="ButtonSection" Src="~/_controltemplates/ButtonSection.ascx" %>
<%@ Register TagPrefix="wssawc" Namespace="Microsoft.SharePoint.WebControls" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>

<asp:Content ID="PageHead" ContentPlaceHolderID="PlaceHolderAdditionalPageHead" runat="server">
</asp:Content>

<asp:Content ID="Main" ContentPlaceHolderID="PlaceHolderMain" runat="server">
    <table width="100%" class="propertysheet" cellspacing="0" cellpadding="0" border="0">
        <tr>
            <td class="ms-descriptionText">
                <asp:Label ID="LabelMessage" runat="server" EnableViewState="False" class="ms-descriptionText" />
            </td>
        </tr>
        <tr>
            <td class="ms-error">
                <asp:Label ID="LabelErrorMessage" runat="server" EnableViewState="False" />
            </td>
        </tr>
        <tr>
            <td class="ms-descriptionText">
                <asp:ValidationSummary ID="ValSummary" HeaderText="<%$SPHtmlEncodedResources:spadmin, ValidationSummaryHeaderText%>"
                    DisplayMode="BulletList" ShowSummary="True" runat="server"></asp:ValidationSummary>
            </td>
        </tr>
    </table>

    <style>
        .ms-inputformcontrols
        {
            width: 480px;
        }
    </style>

    <table border="0" cellspacing="0" cellpadding="0" width="100%">
        <wssuc:InputFormSection Title="Auth0 settings" runat="server">
            <template_description>
			    <SharePoint:EncodedLiteral ID="EncodedLiteral1" runat="server" text="Specify one Domain/Client ID/Client Secret for each application one by line (these values can be found in Auth0 Settings)." 
                                           EncodeMethod='HtmlEncodeAllowSimpleTextFormatting'/>
		    </template_description>
            
            <template_inputformcontrols>

			    <table border="0" width="100%" cellspacing="0" cellpadding="0" class="authoringcontrols">
				    <wssuc:InputFormControl ID="InputFormControl1" LabelText="InputFormControlLabelText">
					    <Template_control>
						    <SharePoint:EncodedLiteral ID="EncodedLiteral3" runat="server" text="Domain (for example contoso.auth0.com):" EncodeMethod='HtmlEncode'/>
						    <br/>
						    <wssawc:InputFormTextBox title="Domain" class="ms-input" ID="DomainTextBox" TextMode="MultiLine" Rows="3" Runat="server" Width="100%" />
						    <br/>
					    </Template_control>
				    </wssuc:InputFormControl>
				    <wssuc:InputFormControl ID="InputFormControl2" LabelText="InputFormControlLabelText">
					    <Template_control>
						    <br/>
						    <SharePoint:EncodedLiteral ID="EncodedLiteral4" runat="server" text="Client ID:" EncodeMethod='HtmlEncode'/>
						    <br/>
						    <wssawc:InputFormTextBox title="Client ID" class="ms-input" ID="ClientIdTextBox" TextMode="MultiLine" Rows="3" Runat="server" Width="100%" />
						    <br/>
					    </Template_control>
				    </wssuc:InputFormControl>
				    <wssuc:InputFormControl ID="InputFormControl3" LabelText="InputFormControlLabelText">
					    <Template_control>
						    <br/>
						    <SharePoint:EncodedLiteral ID="EncodedLiteral5" runat="server" text="Client Secret:" EncodeMethod='HtmlEncode'/>
						    <br/>
						    <wssawc:InputFormTextBox title="Client Secret" class="ms-input" ID="ClientSecretTextBox" TextMode="MultiLine" Rows="3" Runat="server" Width="100%" />
						    <br/>
					    </Template_control>
				    </wssuc:InputFormControl>
                    <wssuc:InputFormControl ID="InputFormControl4" LabelText="InputFormControlLabelText">
					    <Template_control>
                            <br/>
						    <SharePoint:EncodedLiteral ID="EncodedLiteral2" runat="server" text="Identifier User Field:" EncodeMethod='HtmlEncode'/>
						    <br/>
						    <wssawc:InputFormTextBox title="Identifier User Field" class="ms-input" ID="IdentifierUserFieldTextBox" Runat="server" Columns="30" MaxLength="255" />
						    <br/>
					    </Template_control>
				    </wssuc:InputFormControl>
			    </table>
                <br|
		    </template_inputformcontrols>
        </wssuc:InputFormSection>

        <wssuc:InputFormSection runat="server" Title="People picker display text" Description="This text is displayed in the header of the results list in the people picker control." id="IFSGeneralSettings2">
            <template_inputformcontrols>
				<wssawc:InputFormTextBox title="Text to display" class="ms-input" ID="PickerEntityGroupNameTextBox" 
                                         Columns="30" Runat="server" MaxLength="255" />
			</template_inputformcontrols>
        </wssuc:InputFormSection>
        
        <wssuc:ButtonSection runat="server">
            <template_buttons>
			    <asp:Button UseSubmitBehavior="false" runat="server" class="ms-ButtonHeightWidth" OnClick="BtnOK_Click" Text="<%$Resources:wss,multipages_okbutton_text%>" id="BtnOK" accesskey="<%$Resources:wss,okbutton_accesskey%>"/>
		    </template_buttons>
        </wssuc:ButtonSection>
    </table>
</asp:Content>

<asp:Content ID="PageTitle" ContentPlaceHolderID="PlaceHolderPageTitle" runat="server">
    Auth0 Configuration
</asp:Content>

<asp:Content ID="PageTitleInTitleArea" ContentPlaceHolderID="PlaceHolderPageTitleInTitleArea" runat="server">
    Auth0 Configuration - <asp:Label ID="LabelVersion" runat="server" EnableViewState="False" />
</asp:Content>