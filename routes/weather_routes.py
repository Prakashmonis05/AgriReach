from flask import Blueprint, render_template, request
import requests

weather = Blueprint('weather', __name__)



@weather.route("/weather", methods=["GET", "POST"])
def weather_page():
    API_KEY = "a99163c6213649bd9a7133644250211"
    city = "Delhi"  # Default city
    weather_data = None

    # If user searches a specific city
    if request.method == "POST":
        user_city = request.form.get("city", "").strip()
        if user_city:
            city = user_city

    # Fetch weather data
    url = f"https://api.weatherapi.com/v1/forecast.json?key={API_KEY}&q={city}&days=10&aqi=no&alerts=no"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        weather_data = data.get("forecast", {}).get("forecastday", [])

        # Prepare graph data
        dates = [day["date"] for day in weather_data]
        avg_temps = [day["day"]["avgtemp_c"] for day in weather_data]
        max_temps = [day["day"]["maxtemp_c"] for day in weather_data]
        min_temps = [day["day"]["mintemp_c"] for day in weather_data]
        humidities = [day["day"]["avghumidity"] for day in weather_data]
    else:
        weather_data = []
        dates = avg_temps = max_temps = min_temps = humidities = []

    return render_template(
        "weather.html",
        weather_data=weather_data,
        city=city,
        dates=dates,
        avg_temps=avg_temps,
        max_temps=max_temps,
        min_temps=min_temps,
        humidities=humidities,
    )
