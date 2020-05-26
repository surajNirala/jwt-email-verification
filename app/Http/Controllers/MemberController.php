<?php

namespace App\Http\Controllers;

use App\User;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterRequest;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Response;
use App\Events\EmailVerificationApiEvent;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Auth\Access\AuthorizationException;

class MemberController extends Controller
{
    protected $data = [];
    public function __construct()
        {
        $this->data = [
        'status' => false,
        'code' => 401,
        'data' => null,
        'err' => [
        'code' => 1,
        'message' => 'Unauthorized'
        ]
        ];
    }

    public function login(Request $request)
    { 
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ]);
        if ($validator->fails()) {
            $messages = $validator->messages();
            $data = [
                'status' => false,
                'code' => 422,
                'data' => null,
                'err' => [
                    'errors' => $messages
                ]
            ];
            return response()->json($data, 422);
        }
        $credentials = $request->only(['email', 'password']);
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
            throw new Exception('invalid_credentials');
            }
            $email_verified_at = auth()->user()->email_verified_at;
            if (empty($email_verified_at))
            {
                $data = [
                    'status' => false,
                    'code' => 401,
                    'data' => null,
                    'err' => [
                        'error' => 'Your have not verified your email.'
                    ]
                ];
                return response()->json($data, 401);   
            }
            $this->data = [
                'status' => true,
                'code' => 200,
                'data' => [
                '_token' => $token
                ],
                'err' => null
            ]; 
        } catch (Exception $e) {
            $this->data['err']['message'] = $e->getMessage();
            $this->data['code'] = 401;
        } catch (JWTException $e) {
            $this->data['err']['message'] = 'Could not create token';
            $this->data['code'] = 500;
        }
        return response()->json($this->data, $this->data['code']);
    }
/**
*I do not elaborate as the user registers method used here before, as described in RegisterRequest.
* @param RegisterRequest $request
* @return JsonResponse
*/
public function register(Request $request)
{
    
    $this->validator($request->all())->validate();
    $user = User::create([
        'name' => $request->post('name'),
        'email' => $request->post('email'),
        'password' => Hash::make($request->post('password'))
        ]);

    $user->notify(new \App\Notifications\VerifyEmail());
    // event(new EmailVerificationApiEvent($user));
    // event(new Registered($user));
    // $user->sendEmailVerificationNotification();

    $this->data = [
        'status' => true,
        'code' => 200,
        'message' => 'Thanks for signing up! Please check your email to complete your registration.',
        'data' => [
        'User' => $user
        ],
        'err' => null
        ];
    return response()->json($this->data, $this->data['code']);
}
/**
* Bring the details of the verified user.
*
* @return JsonResponse
*/
public function detail()
{
    
    $email_verified_at = auth()->user()->email_verified_at;
    if (empty($email_verified_at))
    {
        $data = [
            'status' => false,
            'code' => 401,
            'data' => null,
            'err' => [
                'error' => 'Your have not verified your email.'
            ]
        ];
            return response()->json($data, 401);   
    }
    $this->data = [
    'status' => true,
    'code' => 200,
    'data' => [
    'User' => auth()->user()
    ],
    'err' => null
    ];
    return response()->json($this->data);
}
/**
*Log out the user and make the token unusable.
* @return JsonResponse
*/
public function logout(Request $request)
{
    // auth()->logout(true);
    
    $validator = Validator::make($request->all(), [
        'token' => 'required',
    ]);
    if ($validator->fails()) {
        $messages = $validator->messages();
        $data = [
            'status' => false,
            'code' => 422,
            'data' => null,
            'err' => [
                'errors' => $messages
            ]
        ];
        return response()->json($data, 422);
    }
    try {
        JWTAuth::invalidate($request->token);

        $data = [
            'status' => true,
            'code' => 200,
            'data' => [
            'message' => 'Successfully logged out'
            ],
            'err' => null
            ];
        return response()->json($data);
    } catch (JWTException $exception) {
        $data = [
            'status' => true,
            'code' => 500,
            'data' => [
            'message' => 'Sorry, the user cannot be logged out.'
            ],
            'err' => null
            ];
            return response()->json($data);
    }
}
/**
* Renewal process to make JWT reusable after expiry date.
* @return JsonResponse
*/
public function refresh()
{
    $data = [
    'status' => true,
    'code' => 200,
    'data' => [
    '_token' => auth()->refresh()
    ],
    'err' => null
    ];
    return response()->json($data, 200);
}
protected function validator(array $data)
{
    return Validator::make($data, [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8|confirmed',
    ]);
}

    public function resend(Request $request)
    {
        if ( $request->user()->hasVerifiedEmail() ) {
            $data = [
                'status' => true,
                'code' => 200,
                'message' => 'Email address '.$request->user()->getEmailForVerification().' is already verified.',
                'err' => null
            ];
            return response()->json($data, 200);
            // return response()->json('Email address '.$request->user()->getEmailForVerification().' is already verified.');
        }

        $request->user()->notify(new \App\Notifications\VerifyEmail());

        if($request->wantsJson()){
            $data = [
                'status' => true,
                'code' => 200,
                'data' => [
                'message' => 'Resend email verification link on '.$request->user()->email
                ],
                'err' => null
            ];
            return response()->json($data);
        } 
    }
    public function emailVerify(Request $request)
    {
        try {
        $validator = Validator::make($request->all(), [
            'token' => 'required|string',
        ]);
        if ($validator->fails()) {
            $messages = $validator->messages();
            $data = [
                'status' => false,
                'code' => 422,
                'data' => null,
                'err' => [
                    'errors' => $messages
                ]
            ];
            return response()->json($data, 422);
        }
        \Tymon\JWTAuth\Facades\JWTAuth::getToken();
            \Tymon\JWTAuth\Facades\JWTAuth::parseToken()->authenticate();
        if ( ! $request->user() ) {
                $data = [
                    'status' => false,
                    'code' => 401,
                    'message' => 'Invalid token.',
                    'err' => null
                ];
                return response()->json($data, 401);
            }
            
            if ( $request->user()->hasVerifiedEmail() ) {
                $data = [
                    'status' => true,
                    'code' => 200,
                    'message' => 'Email address '.$request->user()->getEmailForVerification().' is already verified.',
                    'err' => null
                ];
                return response()->json($data, 200);
                // return response()->json('Email address '.$request->user()->getEmailForVerification().' is already verified.');
            }
        $request->user()->markEmailAsVerified();
        $data = [
            'status' => true,
            'code' => 200,
            'message' => 'Email Verified successfully.',
            'err' => null
        ];
        return response()->json($data, 200);
    } catch (\Exception $e) {
        $data = [
            'status' => false,
            'code' => 500,
            'message' => "Internal Server Error.",//$e->getMessage(),
            'err' => null
        ];
        return response()->json($data, 500);
    }   
    }

}
