<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\SendNotificationRequest;
use App\HttpResponse\HTTPResponse;
use App\Models\User;
use Illuminate\Http\Request;

class NotificationController extends Controller
{


    use HTTPResponse;
    public function BasicSendNotification($title , $body , $FcmToken){
        $url = 'https://fcm.googleapis.com/fcm/send';
        $server_key = "AAAAhggAXOM:APA91bFlPweIZXPYUlmObCTFaQlvzm3Op6G_fyq9RJcpN81kmekCaEz00vbhnW3dQLZredAQYCD1qg6kswC5H0ZAuNrucMnEqNVGfnyGp5woSd7_WENU7zNWOHIE-CiUBmXalBr_btCC";
        $date = [
            'registration_ids' => $FcmToken,
            'notification' => [
                'title' => $title,
                'body' => $body
            ]
        ];

        $encodedData = json_encode($date);

        $headers = [
            'Authorization: key='.$server_key,
            'Content-Type: application/json'
        ];

        $ch = curl_init();

        curl_setopt($ch , CURLOPT_URL , $url);
        curl_setopt($ch , CURLOPT_POST , true);
        curl_setopt($ch , CURLOPT_HTTPHEADER , $headers);
        curl_setopt($ch , CURLOPT_RETURNTRANSFER , true);
        curl_setopt($ch , CURLOPT_SSL_VERIFYHOST , 0);
        curl_setopt($ch , CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_1);
        curl_setopt($ch , CURLOPT_SSL_VERIFYPEER , false);
        curl_setopt($ch , CURLOPT_POSTFIELDS , $encodedData);

        $result = curl_exec($ch);

        if ($result === FALSE){
            return HelperFunction::ServerErrorResponse();
        }

        curl_close($ch);

        return $this->success($result , __('messages.notification_controller.send_successfully'));
    }

    public function sendNotificationForAllUser(SendNotificationRequest $request){
        try {
            $tokens = User::whereNotNull('device_notification_id')->pluck('device_notification_id')->all();
            $result = $this->BasicSendNotification($request->title , $request->body , $tokens);
            return $result;
        }catch (\Throwable $th){
            return $this->error($th->getMessage() , 500);
        }
    }

    public function addNewCourseNotification($course){
        try {
            $title = 'اضافة دورة تدريبة جديدة جديد';
            $body =  'تمت اضافة دورة تدريبة جديدة تحت عنوان ' . $course->name;
            $tokens = User::whereNotNull('device_notification_id')->pluck('device_notification_id')->all();
            $result = $this->BasicSendNotification($title, $body , $tokens);
            return $result;
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
