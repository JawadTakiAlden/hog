<?php

namespace App\Http\Controllers;

use App\Exports\ActivationCodesExport;
use App\Http\HelperFunction;
use App\Http\Requests\CheckCodeRequest;
use App\Http\Resources\CheckActivationCodeResource;
use App\HttpResponse\HTTPResponse;
use App\Models\ActivationCode;
use App\Http\Requests\StoreActivationCodeRequest;
use App\Http\Requests\UpdateActivationCodeRequest;
use App\Models\Course;
use App\Models\CourseCanActivated;
use App\Models\ExportableFile;
use App\Types\CodeType;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Maatwebsite\Excel\Facades\Excel;
use Illuminate\Support\Facades\File;

class ActivationCodeController extends Controller
{
    use HTTPResponse;

    private function getRandomCode(){
        return strtoupper(Str::random(6));
    }

    public function store(StoreActivationCodeRequest $request){
        try {
            $type = $request->get('type');
            $courses = $request->get('courses');
            $quantity = intval($request->get('quantity'));
            $exportData = collect();
            DB::beginTransaction();
            if ($type === CodeType::SINGLE){
//                handle single code type
                if (count($courses) > 1){
                    return $this->error(__("messages.activation_code_controller.error.select_more_than_one_course") , 422);
                }
                for ($i = 0 ; $i < $quantity ; $i++){
                    $code = $this->getRandomCode();
                    while (ActivationCode::where('code', $code)->exists()) {
                        $code = Str::random(6);
                    }
                    $newActivationCode = ActivationCode::create([
                        'code' => $code,
                        'times_of_usage' => count($courses),
                        'type' => $type
                    ]);
                    $exportData->push($newActivationCode);
                    CourseCanActivated::create([
                        'activation_code_id' => $newActivationCode->id,
                        'course_id' => $courses[0],
                    ]);
                }
            }else if ($type === CodeType::SHARED) {
                if (count($courses) <= 1){
                    return $this->error(__("messages.activation_code_controller.error.select_less_than_two_course") , 422);
                }
                for ($i = 0 ; $i < $quantity ; $i++){
                    $code = $this->getRandomCode();
                    while (ActivationCode::where('code', $code)->exists()) {
                        $code = Str::random(15);
                    }
                    $newActivationCode = ActivationCode::create([
                        'code' => $code,
                        'times_of_usage' => count($courses),
                        'type' => $type
                    ]);
                    $exportData->push($newActivationCode);
                    foreach ($courses as $course){
                        CourseCanActivated::create([
                            'activation_code_id' => $newActivationCode->id,
                            'course_id' => $course,
                        ]);
                    }
                }
            }else if ($type === CodeType::SHARED_SELECTED){
                for ($i = 0 ; $i < $quantity ; $i++) {
                    $code = $this->getRandomCode();
                    while (ActivationCode::where('code', $code)->exists()) {
                        $code = Str::random(15);
                    }
                    $newActivationCode = ActivationCode::create([
                        'code' => $code,
                        'times_of_usage' => $request->number_of_courses,
                        'type' => $type
                    ]);
                    $exportData->push($newActivationCode);
                }
            }else {
                for ($i = 0 ; $i < $quantity ; $i++) {
                    $code = $this->getRandomCode();
                    while (ActivationCode::where('code', $code)->exists()) {
                        $code = Str::random(15);
                    }
                    $newActivationCode = ActivationCode::create([
                        'code' => $code,
                        'times_of_usage' => 1,
                        'type' => $type
                    ]);
                    $exportData->push($newActivationCode);
                }
            }
            $fileName = "";
            $currentDateTime = Carbon::now();
            $formattedDateTime = $currentDateTime->format('Y-m-d h:i:s A');
            if ($request->title){
                $fileName = $request->title . '_' . $currentDateTime . '.xlsx';
            }else{
                $fileName = $quantity . ' activation codes from type ' . $type  . ' in ' . $formattedDateTime.".xlsx";
            }
            $folder = 'excel_files';
            $filePath = $folder . '/' . $fileName;
            $coursesNameSpreatedByComma = collect($courses)->map(fn($course) =>
                Course::where('id' , $course)->pluck('name')
            )->implode('| ');
             $exportableFile = ExportableFile::create([
               'path' => $fileName,
               'type_of_code' => $type,
               'courses_name' => $coursesNameSpreatedByComma
            ]);
            Excel::store(new ActivationCodesExport($exportData->toArray()), $filePath);
            DB::commit();
            return $this->success($exportableFile->path , __("messages.activation_code_controller.generate_codes_successfully"));
        }catch (\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function checkCode(CheckCodeRequest $request){
        try {
            $code = ActivationCode::where('code' , $request->code)->first();
            if (!$code){
                return $this->error(__('messages.error.not_found') , 404);
            }
            return $this->success(CheckActivationCodeResource::make($code));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getUnExpiredCodes(){
        try {
            $codes = ActivationCode::where('times_of_usage' , '>' , 0)->get();
            return $this->success($codes);
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
