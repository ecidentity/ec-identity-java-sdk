package io.ecidentity.integration.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.AbstractX500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.util.Hashtable;

public class EcStyle extends AbstractX500NameStyle {

    public static final ASN1ObjectIdentifier id = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.1").intern();
    public static final ASN1ObjectIdentifier emailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    public static final ASN1ObjectIdentifier givenName = new ASN1ObjectIdentifier("2.5.4.42").intern();
    public static final ASN1ObjectIdentifier surname = new ASN1ObjectIdentifier("2.5.4.4").intern();
    public static final ASN1ObjectIdentifier dateOfBirth = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1").intern();
    public static final ASN1ObjectIdentifier placeOfBirth = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.17").intern();
    public static final ASN1ObjectIdentifier countryOfCitizenship = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4").intern();
    public static final ASN1ObjectIdentifier gender = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3").intern();
    public static final ASN1ObjectIdentifier documentNumber = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.16").intern();
    public static final ASN1ObjectIdentifier dateOfExpire = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.26").intern();
    public static final ASN1ObjectIdentifier documentClass = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.27").intern();
    public static final ASN1ObjectIdentifier documentCountry = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.28").intern();
    public static final ASN1ObjectIdentifier personalNumber = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.30").intern();
    public static final ASN1ObjectIdentifier portrait = new ASN1ObjectIdentifier("1.3.6.1.4.1.50715.1.6").intern();

    public static final ASN1ObjectIdentifier unstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    public static final ASN1ObjectIdentifier unstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;

    private static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols;
    private static final Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp;
    protected final Hashtable<ASN1ObjectIdentifier, String> defaultSymbols;
    protected final Hashtable<String, ASN1ObjectIdentifier> defaultLookUp;

    public static final X500NameStyle INSTANCE;

    protected EcStyle() {
        this.defaultSymbols = copyHashTable(DefaultSymbols);
        this.defaultLookUp = copyHashTable(DefaultLookUp);
    }

    public String oidToDisplayName(ASN1ObjectIdentifier var1) {
        return (String) DefaultSymbols.get(var1);
    }

    public String[] oidToAttrNames(ASN1ObjectIdentifier var1) {
        return IETFUtils.findAttrNamesForOID(var1, this.defaultLookUp);
    }

    public ASN1ObjectIdentifier attrNameToOID(String var1) {
        return IETFUtils.decodeAttrName(var1, this.defaultLookUp);
    }

    public RDN[] fromString(String var1) {
        return IETFUtils.rDNsFromString(var1, this);
    }

    public String toString(X500Name var1) {
        StringBuffer var2 = new StringBuffer();
        boolean var3 = true;
        RDN[] var4 = var1.getRDNs();

        for (RDN rdn : var4) {
            if (var3) {
                var3 = false;
            } else {
                var2.append(',');
            }

            IETFUtils.appendRDN(var2, rdn, this.defaultSymbols);
        }

        return var2.toString();
    }

    static {
        DefaultSymbols = new Hashtable();
        DefaultLookUp = new Hashtable();

        DefaultLookUp.put("id", id);
        DefaultLookUp.put("e", emailAddress);
        DefaultLookUp.put("emailaddress", emailAddress);
        DefaultLookUp.put("givenname", givenName);
        DefaultLookUp.put("surname", surname);
        DefaultLookUp.put("dateofbirth", dateOfBirth);
        DefaultLookUp.put("placeofbirth", placeOfBirth);
        DefaultLookUp.put("countryofcitizenship", countryOfCitizenship);
        DefaultLookUp.put("gender", gender);
        DefaultLookUp.put("documentnumber", documentNumber);
        DefaultLookUp.put("dateofexpire", dateOfExpire);
        DefaultLookUp.put("documentclass", documentClass);
        DefaultLookUp.put("documentcountry", documentCountry);
        DefaultLookUp.put("personalnumber", personalNumber);
        DefaultLookUp.put("portrait", portrait);

        DefaultLookUp.put("unstructuredaddress", unstructuredAddress);
        DefaultLookUp.put("unstructuredname", unstructuredName);

        DefaultSymbols.put(id, "Id");
        DefaultSymbols.put(emailAddress, "EmailAddress");
        DefaultSymbols.put(givenName, "GivenName");
        DefaultSymbols.put(surname, "Surname");
        DefaultSymbols.put(dateOfBirth, "DateOfBirth");
        DefaultSymbols.put(placeOfBirth, "PlaceOfBirth");
        DefaultSymbols.put(countryOfCitizenship, "CountryOfCitizenship");
        DefaultSymbols.put(gender, "Gender");
        DefaultSymbols.put(documentNumber, "DocumentNumber");
        DefaultSymbols.put(dateOfExpire, "DateOfExpire");
        DefaultSymbols.put(documentClass, "DocumentClass");
        DefaultSymbols.put(documentCountry, "DocumentCountry");
        DefaultSymbols.put(personalNumber, "PersonalNumber");
        DefaultSymbols.put(portrait, "Portrait");

        DefaultSymbols.put(unstructuredAddress, "UnstructuredName");
        DefaultSymbols.put(unstructuredName, "UnstructuredAddress");

        INSTANCE = new EcStyle();
    }
}
