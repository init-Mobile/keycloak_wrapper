part of '../keycloak_wrapper.dart';

/// A wrapper around the Keycloak authentication service. Pached version without token
///
/// Provides functionalities for user authentication, token management, and resource authorization.
class KeycloakWrapper {
  factory KeycloakWrapper({required KeycloakConfig config}) => _instance ??= KeycloakWrapper._(config);

  KeycloakWrapper._(this._keycloakConfig);

  static KeycloakWrapper? _instance;

  bool _isInitialized = false;

  final KeycloakConfig _keycloakConfig;

  late final StreamController<bool> _streamController = StreamController<bool>.broadcast();

  /// Called whenever an error gets caught.
  ///
  /// By default, all errors will be printed into the console.
  void Function(String message, Object error, StackTrace stackTrace) onError =
      (String message, Object error, StackTrace stackTrace) => developer.log(
            message,
            name: 'keycloak_wrapper',
            error: error,
            stackTrace: stackTrace,
          );

  /// The details from making a successful token exchange.
  TokenResponse? _tokenResponse;

  /// Returns the access token string.
  ///
  /// To get the payload, do `JWT.decode(keycloakWrapper.accessToken).payload`.
  String? get accessToken => _tokenResponse?.accessToken;

  /// The stream of the user authentication state.
  ///
  /// Returns true if the user is currently logged in.
  Stream<bool> get authenticationStream => _streamController.stream;

  /// Returns the id token string.
  ///
  /// To get the payload, do `JWT.decode(keycloakWrapper.idToken).payload`.
  String? get idToken => _tokenResponse?.idToken;

  /// Whether this package has been initialized.
  bool get isInitialized => _isInitialized;

  /// Returns the refresh token string.
  ///
  /// To get the payload, do `JWT.decode(keycloakWrapper.refreshToken).payload`.
  String? get refreshToken => _tokenResponse?.refreshToken;

  /// Retrieves the current user information.
  Future<Map<String, dynamic>?> getUserInfo() async {
    _assertInitialization();
    try {
      final Uri url = Uri.parse(_keycloakConfig.userInfoEndpoint);
      final HttpClient client = HttpClient();
      final HttpClientRequest request = await client.getUrl(url)
        ..headers.add(HttpHeaders.authorizationHeader, 'Bearer $accessToken');
      final HttpClientResponse response = await request.close();
      final String responseBody = await response.transform(utf8.decoder).join();

      client.close();
      return jsonDecode(responseBody) as Map<String, dynamic>?;
    } catch (e, s) {
      onError('Failed to fetch user info.', e, s);
      return null;
    }
  }

  /// Initializes the user authentication state and refreshes the token.
  Future<void> initialize() async {
    try {
      _isInitialized = true;
      await login();
    } catch (e, s) {
      _isInitialized = false;
      onError('Failed to initialize plugin.', e, s);
    }
  }

  /// Logs the user in.
  ///
  /// Returns true if login is successful.
  Future<bool> login() async {
    _assertInitialization();
    try {
      _tokenResponse = await _appAuth.authorizeAndExchangeCode(
        AuthorizationTokenRequest(
          _keycloakConfig.clientId,
          _keycloakConfig.redirectUri,
          issuer: _keycloakConfig.issuer,
          scopes: _keycloakConfig.scopes,
          allowInsecureConnections: _keycloakConfig.allowInsecureConnections,
          clientSecret: _keycloakConfig.clientSecret,
        ),
      );

      if (!_tokenResponse.isValid) {
        developer.log('Invalid token response.', name: 'keycloak_wrapper');
      }

      _streamController.add(_tokenResponse.isValid);
      return _tokenResponse.isValid;
    } catch (e, s) {
      onError('Failed to login.', e, s);
      return false;
    }
  }

  /// Logs the user out.
  ///
  /// Returns true if logout is successful.
  Future<bool> logout() async {
    _assertInitialization();
    try {
      final EndSessionRequest request = EndSessionRequest(
        idTokenHint: idToken,
        issuer: _keycloakConfig.issuer,
        postLogoutRedirectUrl: _keycloakConfig.redirectUri,
        allowInsecureConnections: _keycloakConfig.allowInsecureConnections,
      );

      await _appAuth.endSession(request);
      _streamController.add(false);
      return true;
    } catch (e, s) {
      onError('Failed to logout.', e, s);
      return false;
    }
  }

  void _assertInitialization() {
    assert(
      _isInitialized,
      'Make sure the package has been initialized prior to calling this method.',
    );
  }
}
