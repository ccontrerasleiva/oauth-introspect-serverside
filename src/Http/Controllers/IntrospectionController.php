<?php

namespace Tiandgi\OAuthIntrospection\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response as Psr7Response;

class IntrospectionController
{
	private $jwt;
	private $rs;
	private $atr;
	public function __construct(Parser $jwt, ResourceServer $rs, AccessTokenRepository $atr)
	{
		$this->jwt = $jwt;
		$this->resourceServer = $rs;
		$this->accessTokenRepository = $atr;
	}

	public function validToken(ServerRequestInterface $r)
	{
		try {
			$this->resourceServer->validateAuthenticatedRequest($r);

			if (array_get($r->getParsedBody(), 'token_type_hint', 'access_token') !== 'access_token') {
				return $this->notActive();
			}
            
            //Get Access Token
			$at = array_get($r->getParsedBody(), 'token');
			if ($at === null) {
				return $this->notActive();
			}

			$token = $this->jwt->parse($at);
			if (!$this->verifyToken($token)) {
				return $this->errorResponse([
					'error' => [
						'title' => 'Token No Válido'
					]
				]);
			}

			$userModel = config('auth.providers.users.model');
			$user = (new $userModel)->findOrFail($token->getClaim('sub'));

			return $this->jsonResponse([
				'active' => true,
				'username' => $user->email,
				'user' => $user->name,
				'scope' => trim(implode(' ', (array)$token->getClaim('scopes', []))),
				'client_id' => $token->getClaim('aud'),
				'token_type' => 'access_token',
				'expires' => intval($token->getClaim('exp')),
			]);
		} catch (OAuthServerException $oAuthServerException) {
			return $oAuthServerException->generateHttpResponse(new Psr7Response);
		} catch (\Exception $e) {
			return $this->exResponse($e);
		}
	}

	private function notActive() : JsonResponse
	{
		return $this->jsonResponse(['active' => false], 401);
	}

	private function jsonResponse($data, $status = 200) : JsonResponse
	{
		return new JsonResponse($data, $status);
	}

	private function verifyToken(Token $token) : bool
	{
		$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
		$publicKey = 'file://' . Passport::keyPath('oauth-public.key');

		try {
			if (!$token->verify($signer, $publicKey)) {
				return false;
			}

			$data = new ValidationData();
			$data->setCurrentTime(time());

			if (!$token->validate($data)) {
				return false;
			}

			if ($this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jti'))) {
				return false;
			}

			return true;
		} catch (\Exception $e) {
		    return $this->exResponse($e, 401);
		}

		return false;
	}

	private function errorResponse($data, $status = 400) : JsonResponse
	{
		return $this->jsonResponse($data, $status);
	}

	private function exResponse(\Exception $e, $status = 500) : JsonResponse
	{
		return $this->errorResponse([
			'error' => [
				'id' => str_slug(get_class($e) . ' ' . $status),
				'status' => $status,
				'title' => $e->getMessage(),
				'detail' => $e->getTraceAsString()
			],
		], $status);
	}
}
