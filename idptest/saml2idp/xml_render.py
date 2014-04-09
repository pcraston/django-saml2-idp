"""
Functions for creating XML output.
"""
import logging
import string
from xml_signing import get_signature_xml
from xml_templates import ATTRIBUTE, ATTRIBUTE_STATEMENT, \
    ASSERTION_GOOGLE_APPS, ASSERTION_SALESFORCE, RESPONSE, SUBJECT
import saml2idp_metadata
import libxml2
import xmlsec

def _get_attribute_statement(params):
    """
    Inserts AttributeStatement, if we have any attributes.
    Modifies the params dict.
    PRE-REQ: params['SUBJECT'] has already been created (usually by a call to
    _get_subject().
    """
    attributes = params.get('ATTRIBUTES', {})
    if len(attributes) < 1:
        params['ATTRIBUTE_STATEMENT'] = ''
        return
    # Build individual attribute list.
    template = string.Template(ATTRIBUTE)
    attr_list = []
    for name, value in attributes.items():
        subs = { 'ATTRIBUTE_NAME': name, 'ATTRIBUTE_VALUE': value }
        one = template.substitute(subs)
        attr_list.append(one)
    params['ATTRIBUTES'] = ''.join(attr_list)
    # Build complete AttributeStatement.
    stmt_template = string.Template(ATTRIBUTE_STATEMENT)
    statement = stmt_template.substitute(params)
    params['ATTRIBUTE_STATEMENT'] = statement


def _get_in_response_to(params):
    """
    Insert InResponseTo if we have a RequestID.
    Modifies the params dict.
    """
    #NOTE: I don't like this. We're mixing templating logic here, but the
    # current design requires this; maybe refactor using better templates, or
    # just bite the bullet and use elementtree to produce the XML; see comments
    # in xml_templates about Canonical XML.
    request_id = params.get('REQUEST_ID', None)
    if request_id:
        params['IN_RESPONSE_TO'] = 'InResponseTo="%s" ' % request_id
    else:
        params['IN_RESPONSE_TO'] = ''


def _get_subject(params):
    """
    Insert Subject.
    Modifies the params dict.
    """
    template = string.Template(SUBJECT)
    params['SUBJECT_STATEMENT'] = template.substitute(params)


def _sign_assertion(unsigned, template, params):
    signature_xml = get_signature_xml(unsigned, params['ASSERTION_ID'])
    params['ASSERTION_SIGNATURE'] = signature_xml
    signed = template.substitute(params)

    logging.debug('Signed:')
    logging.debug(signed)
    return signed


def _encrypt_assertion(unencrypted):
    # load the rsa key
    # Create and initialize keys manager, we use a simple list based
    # keys manager, implement your own KeysStore klass if you need
    # something more sophisticated
    mngr = xmlsec.KeysMngr()
    config = saml2idp_metadata.SAML2IDP_CONFIG
    key = xmlsec.cryptoAppKeyLoad(config['private_key_file'], xmlsec.KeyDataFormatPem, None, None, None)
    # add the key to the manager
    xmlsec.cryptoAppDefaultKeysMngrAdoptKey(mngr, key)

    # now encrypt the xml
    doc = libxml2.parseDoc(unencrypted)
    # Create encryption template to encrypt XML file and replace
    # its content with encryption result
    enc_data_node = xmlsec.TmplEncData(doc, xmlsec.transformAes128CbcId(), None, xmlsec.TypeEncElement, None, None)
    # put encrypted data in the <enc:CipherValue/> node
    enc_data_node.ensureCipherValue()
    # add <dsig:KeyInfo/>
    key_info_node = enc_data_node.ensureKeyInfo(None)
    # Add <enc:EncryptedKey/> to store the encrypted session key
    enc_key_node = key_info_node.addEncryptedKey(xmlsec.transformRsaPkcs1Id(), None, None, None)
    # put encrypted key in the <enc:CipherValue/> node
    enc_key_node.ensureCipherValue()
    # Add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to <enc:EncryptedKey/>
    key_info_node2 = enc_key_node.ensureKeyInfo(None)
    # Set key name so we can lookup key when needed
    key_info_node2.addKeyName(config['private_key_file'])
    # Create encryption context
    enc_ctx = xmlsec.EncCtx(mngr)
    # Generate a Triple DES key
    key = xmlsec.keyGenerate(xmlsec.keyDataDesId(), 192, xmlsec.KeyDataTypeSession)
    enc_ctx.encKey = key
    # Encrypt the data
    enc_ctx.xmlEncrypt(enc_data_node, doc.getRootElement())


    # Destroy all
    key.destroy()
    mngr.destroy()
    enc_ctx.destroy()
    enc_data_node.freeNode()
    # doc.freeDoc()
    return doc


def _get_assertion_xml(template, parameters, signed=False, encrypted=False):
    # Reset signature.
    params = {}
    params.update(parameters)
    params['ASSERTION_SIGNATURE'] = ''
    template = string.Template(template)

    _get_in_response_to(params)
    _get_subject(params) # must come before _get_attribute_statement()
    _get_attribute_statement(params)

    xml_to_return = template.substitute(params)
    logging.debug('Unsigned:')
    logging.debug(xml_to_return)
    if signed:
        xml_to_return = _sign_assertion(xml_to_return, template, params)
    if encrypted:
        xml_to_return = _encrypt_assertion(xml_to_return)
    return xml_to_return


def get_assertion_googleapps_xml(parameters, signed=False):
    return _get_assertion_xml(ASSERTION_GOOGLE_APPS, parameters, signed)


def get_assertion_salesforce_xml(parameters, signed=False):
    return _get_assertion_xml(ASSERTION_SALESFORCE, parameters, signed)


def get_response_xml(parameters, signed=False):
    """
    Returns XML for response, with signatures, if signed is True.
    """
    # Reset signatures.
    params = {}
    params.update(parameters)
    params['RESPONSE_SIGNATURE'] = ''
    _get_in_response_to(params)

    template = string.Template(RESPONSE)
    unsigned = template.substitute(params)

    logging.debug('Unsigned:')
    logging.debug(unsigned)
    if not signed:
        return unsigned

    # Sign it.
    signature_xml = get_signature_xml(unsigned, params['RESPONSE_ID'])
    params['RESPONSE_SIGNATURE'] = signature_xml
    signed = template.substitute(params)

    logging.debug('Signed:')
    logging.debug(signed)
    return signed
