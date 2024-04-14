<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\AddQuizToChapterRequest;
use App\Http\Requests\DeleteQuestionFromQuiz;
use App\Http\Requests\QuestionFromQuizRequest;
use App\Http\Requests\StoreNewQuestionInQuizRequest;
use App\Http\Requests\StoreQuizRequest;
use App\Http\Requests\UpdateQuizInChapterRequest;
use App\Http\Requests\UpdateQuizRequest;
use App\Http\Resources\ChapterResource;
use App\Http\Resources\QuizResource;
use App\Http\Resources\SimpleQuizResource;
use App\HttpResponse\HTTPResponse;
use App\Models\ChapterQuiz;
use App\Models\Question;
use App\Models\QuestionQuiz;
use App\Models\Quiz;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class QuizController extends Controller
{
    use HTTPResponse;
    public function getAll(){
        try {
            $quizzes = Quiz::orderBy('created_at')->get();
            return $this->success(SimpleQuizResource::collection($quizzes));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function store(StoreQuizRequest $request){
        try {
            DB::beginTransaction();
            $quiz = Quiz::create($request->only(['title' , 'description']));
            foreach ($request->questions as $question){
                QuestionQuiz::create([
                    'question_id' => $question,
                    'quiz_id' => $quiz->id,
                    'is_visible' => $request->is_visible
                ]);
            }
            DB::commit();
            return $this->success(QuizResource::make($quiz) , __("messages.quiz_controller.create"));
        }catch(\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function show($quizID){
        try {
            $quiz = HelperFunction::getQuizByID($quizID);
            if (!$quiz){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(QuizResource::make($quiz));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function updateQuizInChapter(UpdateQuizInChapterRequest $request , $quiz_chapter_id){
        try {
            $quizChapter = ChapterQuiz::where('id' , $quiz_chapter_id)->first();
            if (!$quizChapter){
                return HelperFunction::notFoundResponce();
            }
            $quizChapter->update($request->only(['is_visible' , 'is_free']));
            return $this->success(null, __('messages.quiz_controller.update_quiz_in_chapter'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function update(UpdateQuizRequest $request , $quizID){
        try {
            $quiz = HelperFunction::getQuizByID($quizID);
            if (!$quiz){
                return HelperFunction::notFoundResponce();
            }
            $quiz->update($request->only(['title' , 'description']));
            return $this->success(null, __('messages.quiz_controller.update'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function destroy($quizID){
        try {
            $quiz = HelperFunction::getQuizByID($quizID);
            if (!$quiz){
                return HelperFunction::notFoundResponce();
            }
            $quiz->delete();
            return $this->success(null, __('messages.quiz_controller.delete'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function removeFromCourse($chapterQuizID){
        try {
            $chapterQuiz = ChapterQuiz::where('id' , $chapterQuizID)->first();
            if (!$chapterQuiz){
                return HelperFunction::notFoundResponce();
            }
            $chapterQuiz->delete();
            return $this->success(null,__('messages.quiz_controller.delete_from_chapter'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function addQuestionToQuiz(StoreNewQuestionInQuizRequest $request){
        try {
            DB::beginTransaction();
            $quiz = HelperFunction::getQuizByID($request->quiz_id);
            if (!$quiz){
                return HelperFunction::notFoundResponce();
            }
            foreach ($request->questions as $question){
                if (QuestionQuiz::where('question_id' , $question)->where('quiz_id' , $quiz->id)->exists()){
                    continue;
                }
                QuestionQuiz::create([
                    'question_id' => $question,
                    'quiz_id' => $quiz->id,
                    'is_visible' => $request->is_visible
                ]);
            }
            DB::commit();
            return $this->success(null, __('messages.quiz_controller.questions_added'));
        }catch(\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function deleteQuestionFromQuiz(QuestionFromQuizRequest $request){
        try {
            DB::beginTransaction();
            if ($request->questionQuizzes){
                foreach ($request->questionQuizzes as $questionQuizz){
                    QuestionQuiz::where('id' , $questionQuizz)->delete();
                }
            }
            DB::commit();
            return $this->success(null , __('messages.quiz_controller.delete_question_from_quiz'));
        }catch(\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function hideVisibility(QuestionFromQuizRequest $request){
        try {
            DB::beginTransaction();
            if ($request->questionQuizzes){
                foreach ($request->questionQuizzes as $questionQuizz){
                    QuestionQuiz::where('id' , $questionQuizz)->update([
                        'is_visible' => false
                    ]);
                }
            }
            DB::commit();
            return $this->success(null , __('messages.quiz_controller.visibility_update'));
        }catch(\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function showVisibility(QuestionFromQuizRequest $request){
        try {
            DB::beginTransaction();
            if ($request->questionQuizzes){
                foreach ($request->questionQuizzes as $questionQuizz){
                    QuestionQuiz::where('id' , $questionQuizz)->update([
                        'is_visible' => true
                    ]);
                }
            }
            DB::commit();
            return $this->success(null ,__('messages.quiz_controller.visibility_update'));
        }catch(\Throwable $th){
            DB::rollBack();
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function addQuizToChapter(AddQuizToChapterRequest $request){
        try {
            $quizID = intval($request->quiz_id);
            $chapterID = intval($request->chapter_id);
            $quiz = Quiz::where('id' , $quizID)->first();
            $chapter  = HelperFunction::getChapterByID($chapterID);
            if (!$quiz){
                return HelperFunction::notFoundResponce();
            }
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $isAddedBefore = ChapterQuiz::where('quiz_id' , $quizID)->where('chapter_id' , $chapterID)->exists();
            if ($isAddedBefore){
                return $this->error(__('messages.quiz_controller.error.quiz_added_before_to_chapter'), 422);
            }
            ChapterQuiz::create([
               'chapter_id' => $chapterID,
               'quiz_id' => $quizID,
               'is_visible' => $request->is_visible
            ]);
            return $this->success(null, __('messages.quiz_controller.quiz_to_chapter_successfully'));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
