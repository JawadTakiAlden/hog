<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\StoreChoiceRequest;
use App\Http\Requests\UpdateChoiceRequest;
use App\Http\Resources\QuestionResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Choice;
use Illuminate\Http\Request;

class ChoiceController extends Controller
{
    use HTTPResponse;
    public function store(StoreChoiceRequest $request , $questionID){
        try {
            $question = HelperFunction::getQuestionByID($questionID);
            if (!$question){
                return HelperFunction::notFoundResponce();
            }
            if ($request->is_true){
                $question->choices()->where('is_true' , true)->update(['is_true' => false]);
            }
            Choice::create(array_merge($request->only(['title' , 'is_visible' , 'image' , 'is_true']) , ['question_id' => $questionID] ));
            return $this->success(QuestionResource::make($question) , __('messages.choice_controller.create'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function updateChoice(UpdateChoiceRequest $request , $choiceID){
        try {
            $choice = HelperFunction::getChoiceByID($choiceID);
            if (!$choice){
                return HelperFunction::notFoundResponce();
            }
            $choice->update($request->only(['title','image']));
            return $this->success(QuestionResource::make($choice->question) ,__('messages.choice_controller.update'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($choiceID){
        try {
            $choice = HelperFunction::getChoiceByID($choiceID);
            if (!$choice){
                return HelperFunction::notFoundResponce();
            }
            $choice->delete();
            return $this->success(QuestionResource::make($choice->question) , __('messages.choice_controller.delete'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function  makeChoiceTrue($choiceID){
        try {
            $choice = HelperFunction::getChoiceByID($choiceID);
            if (!$choice){
                return HelperFunction::notFoundResponce();
            }
            $choice->question->choices()->where('is_true' , true)->update([
                'is_true' => false
            ]);
            $choice->update([
                'is_true' => true
            ]);
            return $this->success(QuestionResource::make($choice->question) , __('messages.choice_controller.make_choice_true'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchVisibility($choiceID){
        try {
            $choice = HelperFunction::getChoiceByID($choiceID);
            if (!$choice){
                return HelperFunction::notFoundResponce();
            }
            $choice->update([
                'is_visible' => !$choice->is_visible
            ]);
            return $this->success(QuestionResource::make($choice->question) , __('messages.choice_controller.visibility_switch'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

}
